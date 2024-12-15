EXEC = track_06
LIB_NAME = libtrack.so
SRC_DIR = src
BUILD_DIR = build
TEST_DIR = tests
TEST_EXEC = run_tests

CFLAGS = -Wall -Wextra -std=c17 -g -D_XOPEN_SOURCE=500
LDFLAGS = -shared -fPIC

LOG_FILE ?= 0
ifeq ($(LOG_FILE), 1)
    CFLAGS += -DLOG_TO_FILE
    $(info Logging to file enabled)
endif

LOG_PATH ?= "logs.txt"
CFLAGS += -DLOG_FILE_PATH=\"$(LOG_PATH)\"

SRCS = $(SRC_DIR)/track_06.c $(SRC_DIR)/m_track.c
OBJS = $(BUILD_DIR)/m_track.o $(BUILD_DIR)/track_06.o

LIB_SRCS = $(SRC_DIR)/m_track.c
LIB_OBJS = $(BUILD_DIR)/lib_m_track.o

TEST_SRCS = $(TEST_DIR)/tests.c $(SRC_DIR)/m_track.c
TEST_OBJS = $(BUILD_DIR)/tests.o $(BUILD_DIR)/test_m_track.o

.PHONY: all clean install lib demo test check

all: demo lib

demo: $(EXEC)

test: $(BUILD_DIR)/$(TEST_EXEC)
	./$(BUILD_DIR)/$(TEST_EXEC)

check: test

$(BUILD_DIR)/$(TEST_EXEC): $(TEST_OBJS)
	$(CC) $(TEST_OBJS) -o $@

$(BUILD_DIR)/tests.o: $(TEST_DIR)/tests.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(BUILD_DIR)/test_m_track.o: $(SRC_DIR)/m_track.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(EXEC): $(OBJS)
	$(CC) $(OBJS) -o $(EXEC)

lib: $(BUILD_DIR)/$(LIB_NAME)

$(BUILD_DIR)/$(LIB_NAME): $(LIB_OBJS)
	$(CC) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/m_track.o: $(SRC_DIR)/m_track.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/lib_m_track.o: $(SRC_DIR)/m_track.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

$(BUILD_DIR)/track_06.o: $(SRC_DIR)/track_06.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -include $(SRC_DIR)/m_track.h -c $< -o $@

install: lib
	@mkdir -p $(DESTDIR)/usr/local/lib
	@mkdir -p $(DESTDIR)/usr/local/include
	cp $(BUILD_DIR)/$(LIB_NAME) $(DESTDIR)/usr/local/lib/
	cp $(SRC_DIR)/m_track.h $(DESTDIR)/usr/local/include/
	cp $(SRC_DIR)/logger.h $(DESTDIR)/usr/local/include/
	cp $(SRC_DIR)/records.h $(DESTDIR)/usr/local/include/
	ldconfig

clean:
	rm -rf $(BUILD_DIR) $(EXEC)