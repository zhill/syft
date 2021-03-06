package packages

import (
	"bytes"
	"flag"
	"testing"

	"github.com/anchore/stereoscope/pkg/filetree"

	"github.com/anchore/go-testutils"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/sergi/go-diff/diffmatchpatch"
)

var updateTextPresenterGoldenFiles = flag.Bool("update-text", false, "update the *.golden files for text presenters")

func TestTextDirPresenter(t *testing.T) {
	var buffer bytes.Buffer

	catalog := pkg.NewCatalog()

	// populate catalog with test data
	catalog.Add(pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Type:    pkg.DebPkg,
	})
	catalog.Add(pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Type:    pkg.DebPkg,
	})

	s, err := source.NewFromDirectory("/some/path")
	if err != nil {
		t.Fatalf("unable to create source: %+v", err)
	}
	pres := NewTextPresenter(catalog, s.Metadata)

	// run presenter
	err = pres.Present(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()

	if *updateTextPresenterGoldenFiles {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(actual), string(expected), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}

}

type PackageInfo struct {
	Name    string
	Version string
}

func TestTextImgPresenter(t *testing.T) {
	var buffer bytes.Buffer

	catalog := pkg.NewCatalog()
	img := imagetest.GetFixtureImage(t, "docker-archive", "image-simple")

	_, ref1, _ := img.SquashedTree().File("/somefile-1.txt", filetree.FollowBasenameLinks)
	_, ref2, _ := img.SquashedTree().File("/somefile-2.txt", filetree.FollowBasenameLinks)

	// populate catalog with test data
	catalog.Add(pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Locations: []source.Location{
			source.NewLocationFromImage(string(ref1.RealPath), *ref1, img),
		},
		FoundBy: "dpkg",
		Type:    pkg.DebPkg,
	})
	catalog.Add(pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Locations: []source.Location{
			source.NewLocationFromImage(string(ref2.RealPath), *ref2, img),
		},
		FoundBy:  "dpkg",
		Metadata: PackageInfo{Name: "package-2", Version: "1.0.2"},
		Type:     pkg.DebPkg,
	})

	// stub out all the digests so that they don't affect tests comparisons
	// TODO: update with stereoscope test utils feature when this issue is resolved: https://github.com/anchore/stereoscope/issues/43
	for _, l := range img.Layers {
		l.Metadata.Digest = "sha256:ad8ecdc058976c07e7e347cb89fa9ad86a294b5ceaae6d09713fb035f84115abf3c4a2388a4af3aa60f13b94f4c6846930bdf53"
	}

	s, err := source.NewFromImage(img, "user-image-input")
	if err != nil {
		t.Fatal(err)
	}
	pres := NewTextPresenter(catalog, s.Metadata)
	// run presenter
	err = pres.Present(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	if *updateTextPresenterGoldenFiles {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(actual), string(expected), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}

}
