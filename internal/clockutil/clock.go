package clockutil

import "time"

// Clock abstracts time for background scheduling and expiry logic.
type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time {
	return time.Now()
}
