# Makefile for SE Identity Creator

# Compiler and Archiver
CC = clang
AR = ar
GO = go

# Frameworks needed by the Objective-C code
FRAMEWORKS = -framework Foundation -framework Security -framework LocalAuthentication

# C Flags for Objective-C compilation
# -fobjc-arc: Enable Automatic Reference Counting
# -Wno-unused-command-line-argument: Suppress warning sometimes seen with Cgo flags
CFLAGS = -fobjc-arc -Wno-unused-command-line-argument

# Library name
LIB_NAME = libSEIdentityCreator.a
# Objective-C source and object files
OBJC_SRC = SEIdentityCreator.m
OBJC_OBJ = $(OBJC_SRC:.m=.o)

# Go source file and output binary name
GO_SRC = main.go
GO_BIN = se_identity_tool

# Default target
all: $(GO_BIN)

# Rule to compile Objective-C source to object file
%.o: %.m SEIdentityCreator.h
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to create the static library from object files
$(LIB_NAME): $(OBJC_OBJ)
	$(AR) rcs $@ $^

# Rule to build the Go binary
# It depends on the static library being created first.
# CGO_LDFLAGS includes the frameworks and links our static library.
$(GO_BIN): $(GO_SRC) $(LIB_NAME) SEIdentityCreator.h
	CGO_CFLAGS="$(CFLAGS)" CGO_LDFLAGS="$(FRAMEWORKS) -L. -lSEIdentityCreator" $(GO) build -o $@ $(GO_SRC)

# Target to clean up build files
clean:
	rm -f $(OBJC_OBJ) $(LIB_NAME) $(GO_BIN) se_key_csr.pem se_key_cert.pem

# Phony targets
.PHONY: all clean
