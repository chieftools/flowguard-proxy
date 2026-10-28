package updater

import (
	"slices"
	"testing"
)

func TestAptInstallArgsKeepChangedConfigurationWithoutPrompting(t *testing.T) {
	want := []string{"apt-get", "install", "-y", "--allow-downgrades",
		"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "flowguard=1.2.3"}
	if got := aptInstallArgs("flowguard", "1.2.3"); !slices.Equal(got, want) {
		t.Fatalf("aptInstallArgs = %q, want %q", got, want)
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
