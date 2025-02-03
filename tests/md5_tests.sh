#!/bin/bash

if [ -z "$1" ] || { [ "$1" != "-b" ] && [ "$1" != "-s" ]; }; then
    echo "MD5 Tester."
	echo "bash md5_tests.sh [-s|-b] [-m] "
	echo "-s. Random tests with strings."
	echo "-b. Random tests with binary (Likely to fail due to quotes) (Run with 2>/dev/null to avoid bash complaints)"
	echo "-m. Test memory errors with valgrind (Mind the slowdown)"
	exit
fi

memory_test_flag=false
if [[ "$@" == *"-m"* ]]; then
    memory_test_flag=true
fi

# Number of tests that are generated randomly
num_random_tests=100

# Maximum length of those tests
random_test_max_length=10000

# Counters
failed=0
bad_execution=0
test_n=0

# Exit code 0: Success
# Exit code 20: Memory error
# Exit code 1: Regular failure

# $1: Description
# $2: Input
function testAgainstMd5() {
	((test_n++))

	echo "Test $test_n, $1 (input: $2)" >> test_logs.txt

	# Own test (With or without valgrind)
    if $memory_test_flag; then
        printf "%s" "$2" | valgrind --log-file=/dev/null --error-exitcode=20 --track-fds=yes --leak-check=full --show-leak-kinds=all ./ft_ssl md5 -q 2>/dev/null 1>self_test_result.txt
        self_exit_code=$?
    else
        printf "%s" "$2" | ./ft_ssl md5 -q 2>/dev/null 1>self_test_result.txt
        self_exit_code=$?
    fi

	# Md5 test
	printf "%s" "$2" | md5sum | cut -d ' ' -f 1 >md5sum_test_result.txt

	# Check mem. error
	if [ $self_exit_code -eq 20 ]
	then
		echo "Memory error on test $test_n, $1 (input: $2)" >> failed_test_log.txt
		bad_execution=1
	fi

	# Check own program error
	if [ $self_exit_code -eq 1 ]
	then
		echo "Self reported error on test $test_n, $1 (input: $2)" >> failed_test_log.txt
		bad_execution=1
	fi

	# Check differences between outputs
	if ! diff self_test_result.txt md5sum_test_result.txt > /dev/null; then
		echo "Input difference on $test_n, $1 (input: $2):" >> failed_test_log.txt
		cat self_test_result.txt >> failed_test_log.txt
		cat md5sum_test_result.txt >> failed_test_log.txt
		((failed++))
	fi

	rm md5sum_test_result.txt self_test_result.txt
}
 
rm -f failed_test_log.txt test_logs.txt

# string tests
testAgainstMd5 "Empty string" ""
testAgainstMd5 "Hello world" "Hello, world!"

# Randomized tests
for i in $(seq 1 $num_random_tests); do
	str_len=$((RANDOM % $random_test_max_length))
	if [ "$1" == "-b" ]; then
		random_str=$(head /dev/urandom | head -c $str_len)
	elif [ "$1" == "-s" ]; then
		random_str=$(head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c $str_len)
	fi
	testAgainstMd5 "Random string of length $str_len" "$random_str"
done

# Text feedback
echo "----- MD5 tester -----"
echo "$test_n tests ran. $failed tests failed."
if [ $bad_execution -eq 1 ]
then
	echo "Warning: A memory or self reported error has been found, regardless of md5 output."
fi
echo "Check tests made on md5_test_logs.txt"
echo "Check test failed on failed_test_log.txt"
