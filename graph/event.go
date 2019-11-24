// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"errors"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/graph/db"
	"github.com/OWASP/Amass/v3/stringset"
)

// InsertEvent create an event node in the graph that represents a discovery task.
func (g *Graph) InsertEvent(eventID string) (db.Node, error) {
	// Check if there is an existing start time for this event.
	// If not, then create the node and add the start time/date
	eventNode, err := g.db.ReadNode(eventID)
	if err != nil {
		// Create a node to represent the event
		eventNode, err = g.db.InsertNode(eventID, "event")
		if err != nil {
			return eventNode, err
		}

		g.db.InsertProperty(eventNode, "start", time.Now().Format(time.RFC3339))
		if err != nil {
			return eventNode, err
		}
	} else {
		// Remove an existing 'finish' property
		if properties, err := g.db.ReadProperties(eventNode, "finish"); err == nil {
			for _, p := range properties {
				g.db.DeleteProperty(eventNode, p.Predicate, p.Value)
			}
		}
	}

	// Update the finish property with the current time/date
	g.db.InsertProperty(eventNode, "finish", time.Now().Format(time.RFC3339))
	if err != nil {
		return eventNode, err
	}

	return eventNode, nil
}

// AddNodeToEvent creates an associations between a node in the graph, a data source and a discovery task.
func (g *Graph) AddNodeToEvent(node db.Node, source, tag, eventID string) error {
	if source == "" || tag == "" || eventID == "" {
		return errors.New("Graph: AddNodeToEvent: Invalid arguments provided")
	}

	eventNode, err := g.InsertEvent(eventID)
	if err != nil {
		return err
	}

	sourceNode, err := g.InsertSource(source, tag)
	if err != nil {
		return err
	}

	sourceEdge := &db.Edge{
		Predicate: "used",
		From:      eventNode,
		To:        sourceNode,
	}
	if err := g.InsertEdge(sourceEdge); err != nil {
		return err
	}

	eventEdge := &db.Edge{
		Predicate: source,
		From:      eventNode,
		To:        node,
	}
	if err := g.InsertEdge(eventEdge); err != nil {
		return err
	}

	return nil
}

func (g *Graph) inEventScope(node db.Node, uuid string) bool {
	edges, err := g.db.ReadInEdges(node)
	if err != nil {
		return false
	}

	for _, edge := range edges {
		if g.db.NodeToID(edge.From) == uuid {
			return true
		}
	}

	return false
}

// EventList returns a list of event UUIDs found in the graph.
func (g *Graph) EventList() []string {
	nodes, err := g.db.AllNodesOfType("event")
	if err != nil {
		return nil
	}

	ids := stringset.New()
	for _, node := range nodes {
		ids.Insert(g.db.NodeToID(node))
	}

	return ids.Slice()
}

// EventDomains returns the domains that were involved in the event.
func (g *Graph) EventDomains(uuid string) []string {
	event, err := g.db.ReadNode(uuid)
	if err != nil {
		return nil
	}

	edges, err := g.db.ReadOutEdges(event)
	if err != nil {
		return nil
	}

	domains := stringset.New()
	for _, edge := range edges {
		p, err := g.db.ReadProperties(edge.To, "type")
		if err != nil || len(p) == 0 || p[0].Value != "fqdn" {
			continue
		}

		if d := config.RootDomain(g.db.NodeToID(edge.To)); d != "" {
			domains.Insert(d)
		}
	}

	return domains.Slice()
}

// EventDateRange returns the date range associated with the provided event UUID.
func (g *Graph) EventDateRange(uuid string) (time.Time, time.Time) {
	var start, finish time.Time

	if event, err := g.db.ReadNode(uuid); err == nil {
		if properties, err := g.db.ReadProperties(event, "start", "finish"); err == nil {
			for _, p := range properties {
				if p.Predicate == "start" {
					start, _ = time.Parse(time.RFC3339, p.Value)
				} else {
					finish, _ = time.Parse(time.RFC3339, p.Value)
				}
			}
		}
	}

	return start, finish
}
