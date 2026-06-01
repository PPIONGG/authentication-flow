import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { HelloPage } from "../src/App";

describe("HelloPage", () => {
  it("renders the app heading", () => {
    render(<HelloPage />);
    expect(
      screen.getByRole("heading", { name: /authentication-flow/i }),
    ).toBeInTheDocument();
  });
});
