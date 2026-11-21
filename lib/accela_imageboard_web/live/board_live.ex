defmodule AccelaImageboardWeb.BoardLive do
  @moduledoc """
  A single board at `/b/:slug`: its threads, newest activity first, and the form
  that starts a new thread.

  Threads are paginated with a keyset cursor over `(pinned, bumped_at, id)` so the
  pinned tier stays on top while the rest keeps the classic imageboard bump order.
  Starting a thread is the one write this page performs; the anonymous identity is
  taken from the socket peer data at mount and passed to Ash through the action
  context, never from form parameters.
  """

  use AccelaImageboardWeb, :live_view

  import AccelaImageboardWeb.BoardComponents

  alias AccelaImageboard.Boards.Thread
  alias AccelaImageboardWeb.ClientIp
  alias AccelaImageboardWeb.Content

  @impl true
  def mount(%{"slug" => slug}, _session, socket) do
    case Content.board(slug) do
      {:ok, board} ->
        {threads, next_cursor} = Content.threads(board.id)
        ip_hash = peer_hash(socket)

        {:ok,
         socket
         |> assign(:page_title, "/#{board.slug}/ - #{board.name}")
         |> assign(:not_found, false)
         |> assign(:board, board)
         |> assign(:ip_hash, ip_hash)
         |> assign(:next_cursor, next_cursor)
         |> assign(:thread_form, new_thread_form(board, ip_hash))
         |> stream(:threads, threads)}

      {:error, :not_found} ->
        {:ok,
         socket
         |> assign(:page_title, "Board not found")
         |> assign(:not_found, true)}
    end
  end

  @impl true
  def handle_event("load_more", _params, %{assigns: %{not_found: true}} = socket),
    do: {:noreply, socket}

  def handle_event("load_more", _params, %{assigns: %{next_cursor: nil}} = socket),
    do: {:noreply, socket}

  def handle_event("load_more", _params, socket) do
    {threads, next_cursor} = Content.threads(socket.assigns.board.id, socket.assigns.next_cursor)

    {:noreply,
     socket
     |> assign(:next_cursor, next_cursor)
     |> stream(:threads, threads, at: -1)}
  end

  def handle_event("validate_thread", %{"thread" => params}, socket) do
    form = AshPhoenix.Form.validate(socket.assigns.thread_form, params)
    {:noreply, assign(socket, :thread_form, form)}
  end

  def handle_event("create_thread", %{"thread" => params}, socket) do
    %{board: board, ip_hash: ip_hash} = socket.assigns

    if is_nil(ip_hash) do
      {:noreply,
       put_flash(
         socket,
         :error,
         "Your connection could not be verified. Reload the page and retry."
       )}
    else
      form = AshPhoenix.Form.validate(socket.assigns.thread_form, params)
      submit_thread(socket, board, form)
    end
  end

  defp submit_thread(socket, board, form) do
    case AshPhoenix.Form.submit(form, params: nil) do
      {:ok, thread} ->
        {:noreply, push_navigate(socket, to: ~p"/b/#{board.slug}/t/#{thread.id}")}

      {:error, form} ->
        {:noreply, assign(socket, :thread_form, form)}
    end
  end

  defp new_thread_form(board, ip_hash) do
    Thread
    |> AshPhoenix.Form.for_create(:create,
      as: "thread",
      params: %{"board_id" => board.id},
      context: ClientIp.anonymous_context(ip_hash)
    )
    |> to_form()
  end

  # The poster identity comes from the connection itself (peer address plus, only
  # when the peer is a trusted proxy, forwarded headers) - never from params.
  defp peer_hash(socket) do
    peer_data = get_connect_info(socket, :peer_data)
    headers = get_connect_info(socket, :x_headers) || []
    ClientIp.hash(peer_data && peer_data.address, headers)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash}>
      <%= if @not_found do %>
        <.missing_panel
          title="Board not found"
          message="This board does not exist or has been hidden."
        />
      <% else %>
        <header class="mb-6 space-y-2">
          <div class="flex flex-wrap items-baseline gap-3">
            <span class="font-mono text-sm text-base-content/40">/{@board.slug}/</span>
            <h1 class="text-2xl font-black tracking-tight">{@board.name}</h1>
          </div>
          <p :if={@board.description} class="max-w-2xl text-sm leading-relaxed text-base-content/60">
            {@board.description}
          </p>
          <div
            :if={@board.rules}
            class="max-w-2xl rounded-xl border border-base-300 bg-base-200/50 px-3 py-2 text-xs leading-relaxed text-base-content/60 whitespace-pre-wrap"
          >
            {@board.rules}
          </div>
        </header>

        <section
          :if={not @board.staff_only_threads}
          class="mb-8 rounded-xl border border-base-300 bg-base-100 p-4"
        >
          <h2 class="mb-3 text-sm font-semibold uppercase tracking-wide text-base-content/50">
            Start a thread
          </h2>

          <.form
            for={@thread_form}
            id="new-thread-form"
            phx-submit="create_thread"
            phx-change="validate_thread"
            class="space-y-3"
          >
            <.form_errors form={@thread_form} />

            <.input
              field={@thread_form[:subject]}
              type="text"
              label="Subject"
              maxlength="120"
              placeholder="What is this thread about?"
            />

            <.input
              field={@thread_form[:name]}
              type="text"
              label="Name (optional)"
              maxlength="60"
              placeholder="Anonymous"
            />

            <.input field={@thread_form[:board_id]} type="hidden" />

            <div class="flex items-center justify-end">
              <button
                type="submit"
                id="new-thread-submit"
                class="rounded-lg bg-primary px-4 py-2 text-sm font-semibold text-primary-content transition hover:opacity-90"
              >
                Create thread
              </button>
            </div>
          </.form>
        </section>

        <div id="threads" phx-update="stream" class="space-y-2">
          <div
            id="threads-empty"
            class="hidden only:block rounded-xl border border-dashed border-base-300 p-10 text-center text-sm text-base-content/50"
          >
            No threads yet. Be the first to start one.
          </div>

          <div :for={{dom_id, thread} <- @streams.threads} id={dom_id}>
            <.thread_row thread={thread} board={@board} />
          </div>
        </div>

        <div :if={@next_cursor} class="mt-6 flex justify-center">
          <button
            id="load-more-threads"
            type="button"
            phx-click="load_more"
            class="rounded-lg border border-base-300 px-4 py-2 text-sm font-medium text-base-content/70 transition hover:bg-base-200 hover:text-base-content"
          >
            Older threads
          </button>
        </div>
      <% end %>
    </Layouts.app>
    """
  end
end
