package agent

import (
	"golang.org/x/sys/windows"
)

// IsAdmin reports whether the process runs elevated (or as SYSTEM).
func IsAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// restrictDir replaces the directory's inherited permissions (ProgramData is
// readable by every user) with full control for SYSTEM and Administrators
// only, inherited by the files inside. Under a user's own profile the
// default ACL is already private, so only the system directory is touched.
func restrictDir(dir string) error {
	if !IsAdmin() {
		return nil
	}
	// D:P = protected DACL (no inheritance from ProgramData);
	// OICI = inherited by files and subfolders; FA = full access;
	// SY = LocalSystem, BA = built-in Administrators.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
