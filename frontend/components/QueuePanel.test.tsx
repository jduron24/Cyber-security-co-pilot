import { fireEvent, render, screen } from "@testing-library/react";

import { QueuePanel } from "./QueuePanel";

describe("QueuePanel", () => {
  it("renders queue items and notifies selection", () => {
    const onSelectIncident = vi.fn();

    render(
      <QueuePanel
        queue={[
          { id: "incident_1", label: "INC-1042", site: "site-a", severity: "High", timestamp: "Apr 18, 1:15 PM EDT", state: "Needs review" },
          { id: "incident_2", label: "INC-1038", site: "site-b", severity: "Low", timestamp: null, state: "Closed" },
        ]}
        selectedIncidentId="incident_1"
        queueError={null}
        onSelectIncident={onSelectIncident}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /inc-1038/i }));
    expect(onSelectIncident).toHaveBeenCalledWith("incident_2");
  });
});
