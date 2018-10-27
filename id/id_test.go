package id

import (
	"testing"
)

func TestNew(t *testing.T) {
	firstID := New()
	var secondID string
	for i := 1; i <= 10; i++ {
		secondID = New()
		if firstID == secondID {
			t.Errorf("%d. - Two uuids where the same.\nFirst= %s\nSecond=%s",
				i, firstID, secondID)
		}
		firstID = secondID
	}
}
