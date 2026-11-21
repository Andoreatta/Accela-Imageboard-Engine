defmodule AccelaImageboardWeb.BoardComponents do
  @moduledoc """
  Presentation for the board UI: post cards, thread rows, image galleries and the
  error panel shared by the board and thread LiveViews.

  Everything here is pure rendering - no data access - so it can be reused by any
  view without dragging Ash queries along.
  """

  use AccelaImageboardWeb, :html

  @doc """
  Renders the form-wide errors of an `AshPhoenix.Form`.

  Domain entrypoint errors such as a rate limit or a ban are attached to
  non-attribute fields, so they never show up next to an input; this panel is what
  makes them visible instead of failing silently.
  """
  attr :form, :any, required: true, doc: "an `AshPhoenix.Form` (or `Phoenix.HTML.Form`)"

  def form_errors(assigns) do
    assigns = assign(assigns, :messages, error_messages(assigns.form))

    ~H"""
    <div
      :if={@messages != []}
      id="form-errors"
      class="rounded-xl border border-error/40 bg-error/10 px-3 py-2 text-sm text-error"
      role="alert"
    >
      <ul class="list-inside list-disc space-y-1">
        <li :for={message <- @messages}>{message}</li>
      </ul>
    </div>
    """
  end

  # Errors may arrive as the form's post-submit errors (one `{field, {msg, opts}}`
  # per error) or as a plain translated list, depending on the form type.
  defp form_error_list(%AshPhoenix.Form{just_submitted?: true, submit_errors: errors})
       when is_list(errors) and errors != [],
       do: errors

  defp form_error_list(%AshPhoenix.Form{} = form), do: AshPhoenix.Form.errors(form)
  defp form_error_list(%Phoenix.HTML.Form{errors: errors}), do: errors || []
  defp form_error_list(_form), do: []

  defp error_messages(form) do
    form
    |> form_error_list()
    |> Enum.flat_map(&normalize_error/1)
    |> Enum.uniq()
  end

  defp normalize_error({_field, {message, opts}}) when is_binary(message),
    do: [translate_error({message, opts})]

  defp normalize_error({_field, messages}) when is_list(messages),
    do: Enum.flat_map(messages, &normalize_error/1)

  defp normalize_error({message, opts}) when is_binary(message),
    do: [translate_error({message, opts})]

  defp normalize_error(message) when is_binary(message), do: [message]
  defp normalize_error(other), do: [inspect(other)]

  @doc """
  Renders one post of a thread: header with the poster name, the post number and an
  OP badge, the body with its line breaks preserved, and the attached images.
  """
  attr :post, :map, required: true, doc: "a `AccelaImageboard.Boards.Post` with `media` loaded"
  attr :op?, :boolean, default: false, doc: "whether this post is the thread's original post"

  def post_card(assigns) do
    ~H"""
    <article
      id={"post-#{@post.id}"}
      class={[
        "rounded-xl border bg-base-100 p-4 transition",
        if(@op?, do: "border-primary/30 bg-primary/5", else: "border-base-300")
      ]}
    >
      <header class="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-base-content/50">
        <span class="font-semibold text-base-content/70">
          {poster_name(@post)}
        </span>
        <span class="font-mono">No.{post_number(@post)}</span>
        <span :if={@op?} class="rounded-full bg-primary/15 px-2 py-0.5 font-semibold text-primary">
          OP
        </span>
      </header>

      <p class="whitespace-pre-wrap break-words text-[0.95rem] leading-relaxed">{@post.body}</p>

      <.media_gallery media={@post.media} />
    </article>
    """
  end

  @doc """
  Renders the images attached to a post, each linked to its full-size original.
  """
  attr :media, :list, default: [], doc: "list of `AccelaImageboard.Boards.Media`"

  def media_gallery(assigns) do
    ~H"""
    <div :if={@media != []} class="mt-3 flex flex-wrap gap-2">
      <a
        :for={media <- @media}
        href={~p"/media/#{media.id}"}
        target="_blank"
        rel="noopener noreferrer"
        class="group block overflow-hidden rounded-lg border border-base-300 bg-base-200/40"
      >
        <img
          src={~p"/media/#{media.id}"}
          alt={media.original_filename || "attached image"}
          loading="lazy"
          decoding="async"
          class="max-h-72 w-auto max-w-full object-contain transition group-hover:opacity-90"
        />
      </a>
    </div>
    """
  end

  @doc """
  Renders one thread as a row of the board page.

  Shows the subject (or a placeholder), the poster name, the reply count and the
  last activity, plus badges for pinned, locked and archived threads.
  """
  attr :thread, :map, required: true, doc: "a `AccelaImageboard.Boards.Thread`"
  attr :board, :map, required: true, doc: "the board the thread belongs to"

  def thread_row(assigns) do
    ~H"""
    <.link
      navigate={~p"/b/#{@board.slug}/t/#{@thread.id}"}
      id={"thread-#{@thread.id}"}
      class="group flex flex-col gap-1 rounded-xl border border-base-300 bg-base-100 p-4 transition hover:border-primary/40 hover:shadow-sm"
    >
      <div class="flex flex-wrap items-center gap-2">
        <span
          :if={@thread.pinned}
          class="rounded-full bg-primary/15 px-2 py-0.5 text-xs font-semibold text-primary"
        >
          pinned
        </span>
        <span
          :if={@thread.locked}
          class="rounded-full bg-warning/15 px-2 py-0.5 text-xs font-semibold text-warning"
        >
          locked
        </span>
        <span
          :if={@thread.archived}
          class="rounded-full bg-base-300 px-2 py-0.5 text-xs font-semibold text-base-content/60"
        >
          archived
        </span>
        <span class="text-base font-semibold tracking-tight group-hover:text-primary">
          {thread_subject(@thread)}
        </span>
      </div>

      <div class="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-base-content/50">
        <span>{@thread.name || "Anonymous"}</span>
        <span>{reply_count(@thread)} replies</span>
        <span class="ml-auto font-mono">{format_time(@thread.bumped_at)}</span>
      </div>
    </.link>
    """
  end

  @doc """
  Renders a neutral panel for a board or thread that does not exist (or is hidden).

  The same panel is used for both cases so a hidden board cannot be told apart
  from one that never existed.
  """
  attr :title, :string, default: "Not found"
  attr :message, :string, default: "This page does not exist."

  def missing_panel(assigns) do
    ~H"""
    <div class="rounded-xl border border-dashed border-base-300 p-10 text-center">
      <h1 class="text-xl font-bold tracking-tight">{@title}</h1>
      <p class="mt-2 text-sm text-base-content/60">{@message}</p>
      <.link
        navigate={~p"/"}
        class="mt-4 inline-block text-sm font-semibold text-primary hover:underline"
      >
        Back to the boards
      </.link>
    </div>
    """
  end

  @doc """
  Formats a timestamp in UTC, minute precision, so a rendered page is stable in
  tests and readable for humans.
  """
  @spec format_time(DateTime.t() | NaiveDateTime.t() | nil) :: String.t()
  def format_time(nil), do: ""

  def format_time(%DateTime{} = datetime), do: Calendar.strftime(datetime, "%Y-%m-%d %H:%M UTC")

  def format_time(%NaiveDateTime{} = datetime),
    do: Calendar.strftime(datetime, "%Y-%m-%d %H:%M UTC")

  @doc """
  Short, human-readable post number derived from the time-ordered uuid_v7 id.
  """
  @spec post_number(map()) :: String.t()
  def post_number(%{id: id}) when is_binary(id), do: String.slice(id, 0, 8)

  defp poster_name(%{name: name}) when is_binary(name) and name != "", do: name
  defp poster_name(_post), do: "Anonymous"

  defp thread_subject(%{subject: subject}) when is_binary(subject) and subject != "", do: subject
  defp thread_subject(_thread), do: "Untitled thread"

  defp reply_count(%{post_count: count}) when is_integer(count) and count > 0, do: count - 1
  defp reply_count(_thread), do: 0
end
