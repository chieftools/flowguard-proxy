package updater

import (
	"slices"
	"testing"
)

func TestAptInstallArgsKeepChangedConfigurationWithoutPrompting(t *testing.T) {
	want := []string{"apt-get", "install", "-y", "--allow-downgrades",
		"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "flowguard=1.2.3"}
	if got := aptInstallArgs("flowguard", "1.2.3", true); !slices.Equal(got, want) {
		t.Fatalf("aptInstallArgs = %q, want %q", got, want)
	}
}

func TestAptInstallArgsForceDowngradesOnAptBefore11(t *testing.T) {
	want := []string{"apt-get", "install", "-y", "--force-yes",
		"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "flowguard=1.2.3"}
	if got := aptInstallArgs("flowguard", "1.2.3", false); !slices.Equal(got, want) {
		t.Fatalf("aptInstallArgs = %q, want %q", got, want)
	}
}

func TestAptVersionBefore11(t *testing.T) {
	for output, want := range map[string]bool{
		"apt 1.0.1ubuntu2.24 for amd64 compiled on Oct 10 2019 22:48:21": true,
		"apt 1.0.9.8.6 for amd64 compiled on May 14 2020 16:52:22":       true,
		"apt 0.9.7.9 for amd64 compiled on Mar 18 2015":                  true,
		"apt 1.1.10 for amd64 compiled on Jan 1 2016":                    false,
		"apt 1.2.35 (amd64)": false,
		"apt 2.8.3 (amd64)":  false,
		"":                   false,
		"something else":     false,
	} {
		if got := aptVersionBefore11(output); got != want {
			t.Errorf("aptVersionBefore11(%q) = %v, want %v", output, got, want)
		}
	}
}

func TestYumArgsOnlyUseFlowGuardRepository(t *testing.T) {
	for _, action := range []string{"install", "downgrade"} {
		want := []string{"/usr/bin/dnf", "--disablerepo=*", "--enablerepo=flowguard", action, "-y", "flowguard-1.2.3"}
		if got := yumChangeArgs("/usr/bin/dnf", action, "flowguard", "1.2.3"); !slices.Equal(got, want) {
			t.Fatalf("yumChangeArgs(%s) = %q, want %q", action, got, want)
		}
	}

	want := []string{"--disablerepo=*", "--enablerepo=flowguard", "list", "available", "flowguard-1.2.3*"}
	if got := yumRepoArgs("list", "available", "flowguard-1.2.3*"); !slices.Equal(got, want) {
		t.Fatalf("yumRepoArgs = %q, want %q", got, want)
	}
}
