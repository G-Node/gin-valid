package web

import "os"

func createTestResultDirs(resdir, filename, filecontent string) error {
	err := os.MkdirAll(resdir, 0755)
	if err != nil {
		return err
	}
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(filecontent)
	if err != nil {
		return err
	}
	return nil
}
