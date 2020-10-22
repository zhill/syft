package json

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

type Artifact struct {
	Name      string      `json:"name"`
	Version   string      `json:"version"`
	Type      string      `json:"type"`
	FoundBy   []string    `json:"foundBy"`
	Locations Locations   `json:"locations,omitempty"`
	Metadata  interface{} `json:"metadata,omitempty"`
	Vendor    string      `json:"vendor"`
	AlternateIdentifiers []pkg.PackageIdentifier `json:"alternateIdentifiers"`
}


func NewArtifact(p *pkg.Package, s scope.Scope) (Artifact, error) {
	locations, err := NewLocations(p, s)
	if err != nil {
		return Artifact{}, err
	}

	return Artifact{
		Name:      p.Name,
		Version:   p.Version,
		Type:      string(p.Type),
		FoundBy:   []string{p.FoundBy},
		Locations: locations,
		Metadata:  p.Metadata,
		Vendor:    p.Vendor,
		AlternateIdentifiers: p.AlternateIdentifiers,
	}, nil
}
