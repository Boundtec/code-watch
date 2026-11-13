module example.com/app

go 1.22

require golang.org/x/net v0.20.0

require (
	github.com/pkg/errors v0.9.1
	golang.org/x/text v0.14.0 // indirect
	example.com/local v1.0.0
	example.com/fork v1.0.0
)

replace example.com/local => ../local

replace example.com/fork v1.0.0 => github.com/other/fork v1.2.3
