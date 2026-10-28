package initsys

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

func dir() *fstest.MapFile { return &fstest.MapFile{Mode: fs.ModeDir | 0o755} }

func TestDetect(t *testing.T) {
	tests := []struct {
		name string
		fsys fstest.MapFS
		want Kind
	}{
		{
			name: "systemd booted",
			fsys: fstest.MapFS{"run/systemd/system": dir(), "etc/init.d": dir()},
			want: Systemd,
		},
		{
			name: "upstart on ubuntu 14.04",
			fsys: fstest.MapFS{
				"sbin/initctl":             &fstest.MapFile{Data: []byte{}},
				"etc/init/rc-sysinit.conf": &fstest.MapFile{Data: []byte("start on filesystem\n")},
				"etc/init.d":               dir(),
			},
			want: Upstart,
		},
		{
			name: "initctl without upstart jobs is sysv",
			fsys: fstest.MapFS{
				"sbin/initctl": &fstest.MapFile{Data: []byte{}},
				"etc/init":     dir(),
				"etc/init.d":   dir(),
			},
			want: SysV,
		},
		{
			name: "debian sysvinit",
			fsys: fstest.MapFS{"etc/init.d": dir(), "proc/1/comm": &fstest.MapFile{Data: []byte("init\n")}},
			want: SysV,
		},
		{
			name: "rhel rc.d layout",
			fsys: fstest.MapFS{"etc/rc.d/init.d": dir()},
			want: SysV,
		},
		{
			name: "nothing",
			fsys: fstest.MapFS{},
			want: Unknown,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Detect(test.fsys); got != test.want {
				t.Fatalf("Detect() = %q, want %q", got, test.want)
			}
		})
	}
}
