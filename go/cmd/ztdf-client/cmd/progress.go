package cmd

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type progressBar struct {
	message     string
	width       int
	determinate bool
	updates     chan float64
	done        chan struct{}
	wg          sync.WaitGroup
	stopOnce    sync.Once
}

func newSpinner(message string) *progressBar {
	return newProgressBar(message, false)
}

func newProgressTracker(message string) *progressBar {
	return newProgressBar(message, true)
}

func newProgressBar(message string, determinate bool) *progressBar {
	p := &progressBar{
		message:     message,
		width:       24,
		determinate: determinate,
		updates:     make(chan float64, 1),
		done:        make(chan struct{}),
	}
	p.wg.Add(1)
	go p.loop()
	return p
}

func (p *progressBar) loop() {
	defer p.wg.Done()

	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()

	progress := 0.0
	step := 0

	if p.determinate {
		p.renderDeterminate(progress)
	} else {
		p.renderIndeterminate(step)
	}

	for {
		select {
		case <-p.done:
			p.clearLine()
			return
		case val := <-p.updates:
			if p.determinate {
				progress = clamp(val, 0, 1)
				p.renderDeterminate(progress)
			}
		case <-ticker.C:
			if p.determinate {
				p.renderDeterminate(progress)
			} else {
				step = (step + 1) % (p.width + 1)
				p.renderIndeterminate(step)
			}
		}
	}
}

func (p *progressBar) renderDeterminate(progress float64) {
	filled := int(progress * float64(p.width))
	if filled > p.width {
		filled = p.width
	}
	bar := strings.Repeat("=", filled) + strings.Repeat(" ", p.width-filled)
	percent := int(progress * 100)
	fmt.Printf("\r%s [%s] %3d%%", p.message, bar, percent)
}

func (p *progressBar) renderIndeterminate(step int) {
	filled := step
	if filled > p.width {
		filled = p.width
	}
	bar := strings.Repeat("=", filled) + strings.Repeat(" ", p.width-filled)
	fmt.Printf("\r%s [%s]", p.message, bar)
}

func (p *progressBar) clearLine() {
	totalLen := len(p.message) + p.width + 10
	fmt.Printf("\r%s\r", strings.Repeat(" ", totalLen))
}

func (p *progressBar) Stop(finalMessage string) {
	p.stopOnce.Do(func() {
		close(p.done)
		p.wg.Wait()
		fmt.Printf("%s\n", finalMessage)
	})
}

func (p *progressBar) Update(progress float64) {
	if !p.determinate {
		return
	}
	select {
	case p.updates <- progress:
	default:
		select {
		case <-p.updates:
		default:
		}
		select {
		case p.updates <- progress:
		default:
		}
	}
}

func clamp(val, min, max float64) float64 {
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return val
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dus", d.Microseconds())
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}
