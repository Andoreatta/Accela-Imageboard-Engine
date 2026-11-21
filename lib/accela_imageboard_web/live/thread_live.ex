defmodule AccelaImageboardWeb.ThreadLive do
  @moduledoc """
  A single thread at `/b/:slug/t/:thread_id`: its posts, oldest first, and the reply
  form with an optional image.

  ## The anonymous identity

  The poster identity is computed once at mount from the socket's peer address (and,
  only when the peer is a trusted proxy, from forwarded headers) by
  `AccelaImageboardWeb.ClientIp`, kept in an assign, and handed to Ash through the
  action context. It is never read from params, so a visitor cannot claim somebody
  else's identity; when no peer address is available the domain refuses to attribute
  the action and no post is created.

  ## Image uploads

  A reply may carry one image. The bytes arrive through `Phoenix.LiveView.Upload`, so
  they never pass through `Plug.Parsers` and the endpoint can keep a small global
  body limit. Each file is validated by magic bytes
  (`AccelaImageboard.Media.Validation`), stored under a random key
  (`AccelaImageboard.Media.Storage`) and attached to the post through the
  `Media.attach` action, which only authorizes this flow. If the post cannot be
  created, the stored file is deleted again.

  ## Bumping

  A reply bumps its thread in the domain: `Post.create` runs
  `AccelaImageboard.Boards.Changes.BumpThread`, which stores the new `bumped_at`
  through `Thread.post_bump` under the server-side reply marker. This page
  therefore never writes the thread itself - posting a reply is enough for the
  thread to move back to the top of its board.
  """

  use AccelaImageboardWeb, :live_view

  import AccelaImageboardWeb.BoardComponents

  alias AccelaImageboard.Boards.Media
  alias AccelaImageboard.Boards.Post
  alias AccelaImageboard.Media.Storage
  alias AccelaImageboard.Media.Validation
  alias AccelaImageboardWeb.ClientIp
  alias AccelaImageboardWeb.Content

  @impl true
  def mount(%{"slug" => slug, "thread_id" => thread_id}, _session, socket) do
    with {:ok, board} <- Content.board(slug),
         {:ok, thread} <- Content.thread(board.id, thread_id) do
      {posts, next_cursor} = Content.posts(thread.id)
      ip_hash = peer_hash(socket)

      {:ok,
       socket
       |> assign(:page_title, thread_title(board, thread))
       |> assign(:not_found, false)
       |> assign(:board, board)
       |> assign(:thread, thread)
       |> assign(:ip_hash, ip_hash)
       |> assign(:posts_cursor, next_cursor)
       |> assign(:reply_form, reply_form(thread, ip_hash))
       |> stream(:posts, posts)
       |> allow_upload(:image,
         accept: Validation.extensions(),
         max_entries: 1,
         max_file_size: Validation.limits().max_bytes,
         auto_upload?: true
       )}
    else
      _missing_board_or_thread ->
        {:ok, assign(socket, page_title: "Thread not found", not_found: true)}
    end
  end

  @impl true
  def handle_event("load_more", _params, %{assigns: %{not_found: true}} = socket),
    do: {:noreply, socket}

  def handle_event("load_more", _params, %{assigns: %{posts_cursor: nil}} = socket),
    do: {:noreply, socket}

  def handle_event("load_more", _params, socket) do
    {posts, next_cursor} = Content.posts(socket.assigns.thread.id, socket.assigns.posts_cursor)

    {:noreply,
     socket
     |> assign(:posts_cursor, next_cursor)
     |> stream(:posts, posts, at: -1)}
  end

  def handle_event("validate_post", %{"post" => params}, socket) do
    {:noreply,
     assign(socket, :reply_form, AshPhoenix.Form.validate(socket.assigns.reply_form, params))}
  end

  def handle_event("cancel_upload", %{"ref" => ref}, socket),
    do: {:noreply, cancel_upload(socket, :image, ref)}

  def handle_event("post", %{"post" => params}, socket) do
    %{ip_hash: ip_hash, thread: thread} = socket.assigns

    cond do
      is_nil(ip_hash) ->
        {:noreply,
         put_flash(
           socket,
           :error,
           "Your connection could not be verified. Reload the page and retry."
         )}

      thread.locked or thread.archived ->
        {:noreply, put_flash(socket, :error, "This thread is closed.")}

      uploads_in_progress?(socket) ->
        {:noreply,
         put_flash(socket, :error, "Wait for the image to finish uploading, then post.")}

      true ->
        create_reply(socket, params)
    end
  end

  ## posting

  defp create_reply(socket, params) do
    {stored, rejected} = store_uploads(socket)

    case rejected do
      [reason | _rest] ->
        discard(stored)
        {:noreply, put_flash(socket, :error, upload_error(reason))}

      [] ->
        form = AshPhoenix.Form.validate(socket.assigns.reply_form, params)
        submit_reply(socket, form, stored)
    end
  end

  defp submit_reply(socket, form, stored) do
    case AshPhoenix.Form.submit(form, params: nil) do
      {:ok, post} ->
        created_media = attach_media(stored, post)

        socket =
          socket
          |> after_reply(post)
          |> maybe_warn_about_media(created_media)
          |> put_flash(:info, "Reply posted")

        {:noreply, socket}

      {:error, form} ->
        discard(stored)
        {:noreply, assign(socket, :reply_form, form)}
    end
  end

  defp after_reply(socket, post) do
    socket
    |> assign(:reply_form, reply_form(socket.assigns.thread, socket.assigns.ip_hash))
    |> stream_insert(:posts, load_media(post))
  end

  defp maybe_warn_about_media(socket, {:error, _reason}),
    do: put_flash(socket, :error, "Your post was published, but the image could not be attached.")

  defp maybe_warn_about_media(socket, _ok), do: socket

  defp load_media(post) do
    case Ash.load(post, :media) do
      {:ok, loaded} -> loaded
      {:error, _reason} -> post
    end
  end

  ## uploads

  # Validates and stores every uploaded entry. The callback runs in the upload
  # process, so it returns plain data and never raises for a rejected file.
  defp store_uploads(socket) do
    results = consume_uploaded_entries(socket, :image, &store_entry/2)

    {stored, rejected} = Enum.split_with(results, &match?({:stored, _}, &1))

    {Enum.map(stored, fn {:stored, value} -> value end),
     Enum.map(rejected, fn {:rejected, reason} -> reason end)}
  end

  # One file in, one tagged tuple out: the bytes are validated by signature (the
  # client's content type is only cross-checked, never trusted) and only then
  # written under a server-chosen key.
  defp store_entry(%{path: path}, entry) do
    with {:ok, media} <- Validation.validate(path, entry.client_type),
         {:ok, stored} <- Storage.store(path, media, entry.client_name) do
      {:ok, {:stored, stored}}
    else
      {:error, reason} -> {:ok, {:rejected, reason}}
    end
  end

  defp attach_media([], _post), do: :ok

  defp attach_media(stored, post) do
    Enum.reduce_while(stored, :ok, fn media, :ok ->
      attributes = Map.put(media, :post_id, post.id)

      case Ash.create(Media, attributes,
             action: :attach,
             actor: nil,
             context: %{media_upload: %{post_flow: true}}
           ) do
        {:ok, _media} -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp discard(stored), do: Enum.each(stored, &Storage.delete(&1.storage_key))

  defp uploads_in_progress?(socket) do
    case uploaded_entries(socket, :image) do
      {_done, []} -> false
      {_done, _in_progress} -> true
    end
  end

  defp upload_error(:too_large), do: "That image is too large."
  defp upload_error(:too_small), do: "That image is too small to be an image."
  defp upload_error(:empty_file), do: "That file is empty."
  defp upload_error(:unsupported_type), do: "Only JPEG, PNG, GIF and WebP images are allowed."

  defp upload_error(:content_type_mismatch),
    do: "That file is not the image type it claims to be."

  defp upload_error(:suspicious_content), do: "That file contains markup and was rejected."
  defp upload_error(:unreadable_file), do: "That file could not be read."
  defp upload_error(:storage_failure), do: "The image could not be stored. Try again."
  defp upload_error(_reason), do: "That image was rejected."

  ## identity

  defp peer_hash(socket) do
    peer_data = get_connect_info(socket, :peer_data)
    headers = get_connect_info(socket, :x_headers) || []
    ClientIp.hash(peer_data && peer_data.address, headers)
  end

  defp reply_form(thread, ip_hash) do
    Post
    |> AshPhoenix.Form.for_create(:create,
      as: "post",
      params: %{"thread_id" => thread.id},
      context: ClientIp.anonymous_context(ip_hash)
    )
    |> to_form()
  end

  defp thread_title(board, thread) do
    subject =
      if is_binary(thread.subject) and thread.subject != "",
        do: thread.subject,
        else: "Untitled thread"

    "#{subject} - /#{board.slug}/"
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash}>
      <%= if @not_found do %>
        <.missing_panel
          title="Thread not found"
          message="This thread does not exist, or it belongs to a board that has been hidden."
        />
      <% else %>
        <nav class="mb-4 flex items-center gap-1 text-sm text-base-content/50">
          <.link navigate={~p"/"} class="transition hover:text-base-content">Boards</.link>
          <span aria-hidden="true">/</span>
          <.link navigate={~p"/b/#{@board.slug}"} class="font-mono transition hover:text-base-content">
            /{@board.slug}/
          </.link>
        </nav>

        <header class="mb-6 space-y-2">
          <h1 class="text-2xl font-black tracking-tight">{thread_title_text(@thread)}</h1>
          <div class="flex flex-wrap items-center gap-2 text-xs text-base-content/50">
            <span
              :if={@thread.pinned}
              class="rounded-full bg-primary/15 px-2 py-0.5 font-semibold text-primary"
            >
              pinned
            </span>
            <span
              :if={@thread.locked}
              class="rounded-full bg-warning/15 px-2 py-0.5 font-semibold text-warning"
            >
              locked
            </span>
            <span
              :if={@thread.archived}
              class="rounded-full bg-base-300 px-2 py-0.5 font-semibold text-base-content/60"
            >
              archived
            </span>
            <span>{@thread.post_count} posts</span>
            <span class="font-mono">{format_time(@thread.bumped_at)}</span>
          </div>
        </header>

        <div id="posts" phx-update="stream" class="space-y-3">
          <div
            id="posts-empty"
            class="hidden only:block rounded-xl border border-dashed border-base-300 p-10 text-center text-sm text-base-content/50"
          >
            No posts yet.
          </div>

          <div :for={{dom_id, post} <- @streams.posts} id={dom_id}>
            <.post_card post={post} op?={post.id == @thread.first_post_id} />
          </div>
        </div>

        <div :if={@posts_cursor} class="mt-4 flex justify-center">
          <button
            id="load-more-posts"
            type="button"
            phx-click="load_more"
            class="rounded-lg border border-base-300 px-4 py-2 text-sm font-medium text-base-content/70 transition hover:bg-base-200 hover:text-base-content"
          >
            Load more replies
          </button>
        </div>

        <section
          :if={@thread.locked or @thread.archived}
          class="mt-8 rounded-xl border border-base-300 bg-base-200/40 p-4 text-sm text-base-content/60"
        >
          This thread is closed. It no longer accepts replies.
        </section>

        <section
          :if={not (@thread.locked or @thread.archived)}
          class="mt-8 rounded-xl border border-base-300 bg-base-100 p-4"
        >
          <h2 class="mb-3 text-sm font-semibold uppercase tracking-wide text-base-content/50">
            Reply to this thread
          </h2>

          <.form
            for={@reply_form}
            id="reply-form"
            phx-submit="post"
            phx-change="validate_post"
            class="space-y-3"
          >
            <.form_errors form={@reply_form} />

            <.input
              field={@reply_form[:name]}
              type="text"
              label="Name (optional)"
              maxlength="60"
              placeholder="Anonymous"
            />

            <.input
              field={@reply_form[:body]}
              type="textarea"
              label="Comment"
              rows="4"
              required
              placeholder="Say something worth reading..."
            />

            <.input field={@reply_form[:thread_id]} type="hidden" />

            <div class="space-y-2">
              <label class="block text-sm font-semibold" for="reply-image">Image (optional)</label>
              <p class="text-xs text-base-content/50">
                JPEG, PNG, GIF or WebP, up to {max_image_size()} MB. The file is checked by its
                bytes, not by its name.
              </p>

              <.live_file_input
                upload={@uploads.image}
                id="reply-image"
                class="block w-full cursor-pointer rounded-lg border border-dashed border-base-300 bg-base-200/40 px-3 py-2 text-sm text-base-content/60"
              />

              <div :for={entry <- @uploads.image.entries} class="flex items-center gap-3 text-xs">
                <span class="font-mono text-base-content/60">{entry.client_name}</span>
                <progress
                  value={entry.progress}
                  max="100"
                  class="h-1 w-24 overflow-hidden rounded-full"
                >
                  {entry.progress}%
                </progress>
                <button
                  type="button"
                  phx-click="cancel_upload"
                  phx-value-ref={entry.ref}
                  class="text-error hover:underline"
                >
                  remove
                </button>
                <span :for={error <- upload_errors(@uploads.image, entry)} class="text-error">
                  {upload_error(error)}
                </span>
              </div>

              <p :for={error <- upload_errors(@uploads.image)} class="text-xs text-error">
                {upload_error(error)}
              </p>
            </div>

            <div class="flex items-center justify-end">
              <button
                type="submit"
                id="reply-submit"
                class="rounded-lg bg-primary px-4 py-2 text-sm font-semibold text-primary-content transition hover:opacity-90"
              >
                Post reply
              </button>
            </div>
          </.form>
        </section>
      <% end %>
    </Layouts.app>
    """
  end

  defp thread_title_text(thread) do
    if is_binary(thread.subject) and thread.subject != "",
      do: thread.subject,
      else: "Untitled thread"
  end

  defp max_image_size do
    div(Validation.limits().max_bytes, 1_048_576)
  end
end
