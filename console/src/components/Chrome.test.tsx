import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Explain, tipPosition } from "./Chrome";

const view = { width: 1280, height: 800 };
const size = { width: 280, height: 72 };
const term = (left: number, top: number, width = 60) => ({ left, right: left + width, top, bottom: top + 18 });

// A help tag stays in the window, whatever pane its term is in.
describe("tipPosition", () => {
  it("goes below the term, from its left edge, or its right edge for end", () => {
    expect(tipPosition(term(100, 200), size, "start", view)).toEqual({ left: 100, top: 224 });
    expect(tipPosition(term(600, 200), size, "end", view)).toEqual({ left: 380, top: 224 });
  });

  it("moves in from either side of the window", () => {
    expect(tipPosition(term(1200, 200), size, "start", view)).toEqual({ left: 992, top: 224 });
    expect(tipPosition(term(20, 200), size, "end", view)).toEqual({ left: 8, top: 224 });
  });

  it("goes above a term near the bottom, unless there's no room there either", () => {
    expect(tipPosition(term(100, 760), size, "start", view)).toEqual({ left: 100, top: 682 });
    expect(tipPosition(term(100, 40), size, "start", { width: 1280, height: 120 })).toEqual({ left: 100, top: 64 });
  });
});

describe("Explain", () => {
  afterEach(() => vi.restoreAllMocks());

  it("places its tag inside the window for a term at the right edge", () => {
    vi.spyOn(Element.prototype, "getBoundingClientRect").mockImplementation(function (this: Element) {
      return (this.getAttribute("role") === "tooltip"
        ? { left: 0, right: 280, top: 0, bottom: 72, width: 280, height: 72 }
        : { left: 990, right: 1020, top: 100, bottom: 118, width: 30, height: 18 }) as DOMRect;
    });
    render(<Explain tip="Where the Mac said its key is kept." bare>File</Explain>);
    fireEvent.mouseEnter(screen.getByText("File"));
    const tag = screen.getByRole("tooltip", { hidden: true });
    expect(tag.style.left).toBe(`${window.innerWidth - 8 - 280}px`);
    expect(tag.style.top).toBe("124px");
  });
});
