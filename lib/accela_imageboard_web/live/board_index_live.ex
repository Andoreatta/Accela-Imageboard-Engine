defmodule AccelaImageboardWeb.BoardIndexLive do
  @moduledoc """
  Board index at `/`: every public board, paginated with a keyset cursor.

  This is the entry point of the imageboard: no account, no form, just the list of
  boards. Hidden boards are already filtered out by the domain's `:list_public`
  read action.
  """

  use AccelaImageboardWeb, :live_view

  alias AccelaImageboardWeb.Content

  @impl true
  def mount(_params, _session, socket) do
    {boards, next_cursor} = Content.boards()

    {:ok,
     socket
     |> assign(:page_title, "Boards")
     |> assign(:next_cursor, next_cursor)
     |> stream(:boards, boards)}
  end

  @impl true
  def handle_event("load_more", _params, %{assigns: %{next_cursor: nil}} = socket),
    do: {:noreply, socket}

  def handle_event("load_more", _params, socket) do
    {boards, next_cursor} = Content.boards(socket.assigns.next_cursor)

    {:noreply,
     socket
     |> assign(:next_cursor, next_cursor)
     |> stream(:boards, boards, at: -1)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash}>
      <header class="mb-8 max-w-2xl space-y-2">
        <h1 class="text-3xl font-black tracking-tight">Boards</h1>
        <p class="text-sm leading-relaxed text-base-content/60">
          Pick a board to read its threads or start a new one. No account is needed:
          every post is attributed to a keyed hash of your IP address, never to the
          address itself.
        </p>
      </header>

      <div id="boards" phx-update="stream" class="grid gap-3 sm:grid-cols-2">
        <div
          id="boards-empty"
          class="hidden only:block rounded-xl border border-dashed border-base-300 p-10 text-center text-sm text-base-content/50"
        >
          No boards are open yet.
        </div>

        <div :for={{dom_id, board} <- @streams.boards} id={dom_id}>
          <.link
            navigate={~p"/b/#{board.slug}"}
            class="group flex h-full flex-col gap-1 rounded-xl border border-base-300 bg-base-100 p-4 transition hover:border-primary/40 hover:shadow-sm"
          >
            <span class="font-mono text-xs text-base-content/40">/{board.slug}/</span>
            <span class="text-lg font-semibold tracking-tight transition group-hover:text-primary">
              {board.name}
            </span>
            <span :if={board.description} class="text-sm leading-relaxed text-base-content/60">
              {board.description}
            </span>
          </.link>
        </div>
      </div>

      <div :if={@next_cursor} class="mt-6 flex justify-center">
        <button
          id="load-more-boards"
          type="button"
          phx-click="load_more"
          class="rounded-lg border border-base-300 px-4 py-2 text-sm font-medium text-base-content/70 transition hover:bg-base-200 hover:text-base-content"
        >
          More boards
        </button>
      </div>
    </Layouts.app>
    """
  end
end
