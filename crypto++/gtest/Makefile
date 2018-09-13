CXX = g++

ifeq ($(shell echo $(TEST_DEBUG)|tr [a-z] [A-Z]),YES)
	CXXFLAGS += -D DEBUG 
endif

TARGET = runTests
SRCS = main.cpp util.cpp aesBase.cpp aesECB.cpp aesCBC.cpp aesCFB.cpp aesOFB.cpp aesCTR.cpp \
		 aesCCM.cpp
OBJS = ${SRCS:.cpp=.o}

GTEST_LIBRARIES = -lgtest -lpthread
CRYPTOPP_LIBRARIES = -lcryptopp
LIBS = $(GTEST_LIBRARIES) $(CRYPTOPP_LIBRARIES)

all : $(TARGET)
	@echo $@:$(TARGET)...

$(TARGET) : $(OBJS)
	@echo $@:$^...
	$(CXX) -o $@ $^ $(LIBS)

%.o : %.cpp
	@echo $@:$<...
	$(CXX) -c $< $(CXXFLAGS)

clean:
	@echo $@...
	rm -rf *.o $(TARGET)
