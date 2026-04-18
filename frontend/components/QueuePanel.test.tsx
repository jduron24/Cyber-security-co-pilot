import { fireEvent, render, screen } from "@testing-library/react";

import { QueuePanel } from "./QueuePanel";

describe("QueuePanel", () => {
  it("renders queue items and notifies selection", () => {
    const onSelectIncident = vi.fn();

    render(
      <QueuePanel
        queue={[
          { id: "incident_1", site: "site-a", severity: "High", state: "Needs review" },
          { id: "incident_2", site: "site-b", severity: "Low", state: "Closed" },
        ]}
        selectedIncidentId="incident_1"
        queueError={null}
        onSelectIncident={onSelectIncident}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /incident_2/i }));
    expect(onSelectIncident).toHaveBeenCalledWith("incident_2");
  });
});
