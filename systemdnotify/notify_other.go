//go:build !linux

package systemdnotify

func NotifyReady(status string) error {
	return nil
}

func NotifyStopping(status string) error {
	return nil
}

func NotifyStatus(status string) error {
	return nil
}
