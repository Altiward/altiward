import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Table } from "./Table";

// A column that gives way in a narrow pane is marked in its heading and every cell, so the
// stylesheet can hide it all at once.
describe("Table", () => {
  it("marks a column that gives way in a narrow pane", () => {
    render(
      <Table label="Macs" rows={[{ id: "a", n: 3 }]} rowKey={(r) => r.id}
        columns={[
          { key: "id", title: "Mac", render: (r) => r.id },
          { key: "n", title: "Queued", align: "right", drop: 1, render: (r) => String(r.n) },
        ]} />,
    );
    expect(screen.getByRole("columnheader", { name: "Mac" })).not.toHaveAttribute("class");
    expect(screen.getByRole("columnheader", { name: "Queued" })).toHaveClass("num", "drop-1");
    expect(screen.getByText("3").closest("td")).toHaveClass("num", "drop-1");
  });
});
