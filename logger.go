package main

import (
	"fmt"
	"github.com/logrusorgru/aurora"
)

type logger struct{}

func (l *logger) Debug(message string) {
	fmt.Print(aurora.Yellow(message))
}

func (l *logger) Info(message string) {
	fmt.Print(aurora.Yellow(message))
}

func (l *logger) Warning(message string) {
	fmt.Print(aurora.Yellow(message))
}

func (l *logger) Err(message string) {
	fmt.Print(aurora.Red(message))
}

func (l *logger) Crit(message string) {
	fmt.Print(aurora.Red(message))
}

func (l *logger) Emerg(message string) {
	fmt.Print(aurora.Red(message))
}

