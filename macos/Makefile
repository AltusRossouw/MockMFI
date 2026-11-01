# CarPlayDesk — build, test, bundle.
#
# SwiftPM needs a full Xcode toolchain for XCTest; the Command Line Tools alone
# ship without it. Override DEVELOPER_DIR if Xcode lives elsewhere.

DEVELOPER_DIR ?= /Applications/Xcode.app/Contents/Developer
SWIFT := DEVELOPER_DIR=$(DEVELOPER_DIR) swift
APP := CarPlayDesk.app
CONFIG ?= release

.PHONY: all build test cli app run clean

all: test app

build:
	$(SWIFT) build -c $(CONFIG) --product CarPlayDesk

test:
	$(SWIFT) test

# make cli ARGS="--identity /path/to/mfi"
cli:
	$(SWIFT) run -q carplaydesk-cli $(ARGS)

app: build
	rm -rf $(APP)
	mkdir -p $(APP)/Contents/MacOS $(APP)/Contents/Resources
	cp .build/$(CONFIG)/CarPlayDesk $(APP)/Contents/MacOS/CarPlayDesk
	cp Info.plist $(APP)/Contents/Info.plist
	codesign --force --sign - $(APP) >/dev/null
	@echo "built $(APP)"

run: app
	open $(APP)

clean:
	rm -rf .build $(APP)
