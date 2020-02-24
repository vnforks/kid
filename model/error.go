package model

import (
	"github.com/pkg/errors"
)

var (
	// ErrResourceNotFound is returned when an attempt get a resource that is existing.
	ErrResourceNotFound = errors.New("resource not found")
)
