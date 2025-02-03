#!/bin/bash

if [ -z "$1" ] || { [ "$1" != "-b" ] && [ "$1" != "-s" ]; }; then
    echo "BASE64 Tester."
	echo "bash base64_tests.sh [-s|-b] [-m] "
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
function testAgainstOpenssl() {
	((test_n++))

	echo "Test $test_n, $1. Encoding test." >> test_logs.txt
	echo "Test $test_n, $1. Encoding test."

	## -- TEST ENCODING -- ##

	# Own test (With or without valgrind)
    if $memory_test_flag; then
        printf "%s" "$2" | valgrind --log-file=/dev/null --error-exitcode=20 --track-fds=yes --leak-check=full --show-leak-kinds=all ./ft_ssl base64 2>>failed_test_log.txt 1>self_test_result.txt
        self_exit_code=$?
    else
        printf "%s" "$2" | ./ft_ssl base64 2>>failed_test_log.txt 1>self_test_result.txt
        self_exit_code=$?
    fi

	# OpenSSL Output
	printf "%s" "$2" | openssl base64 >openssl_test_result.txt

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
	if ! diff self_test_result.txt openssl_test_result.txt > /dev/null; then
		echo "Input difference on $test_n, $1 (input: $2):" >> failed_test_log.txt
		cat self_test_result.txt >> failed_test_log.txt
		cat openssl_test_result.txt >> failed_test_log.txt
		echo "FAILED: BASE64: Test $test_n, $1. Encode."
		((failed++))
	fi

	## -- TEST DECODING -- ##

	((test_n++))

	# Both programs should be able to decode self's output.
	# Openssl expects a newline. So can't use this directly.
	test_case=$(cat self_test_result.txt)
	echo "Test $test_n, $1 (input: $test_case). Decoding test." >> test_logs.txt
	echo "Test $test_n, $1. Decode test."

	# Own test
	# Try W.O newline on printf
    if $memory_test_flag; then
        printf "%s\n" "$test_case" | valgrind --log-file=/dev/null --error-exitcode=20 --track-fds=yes --leak-check=full --show-leak-kinds=all ./ft_ssl base64 -d 2>failed_test_log.txt 1>self_test_result.txt
        self_exit_code=$?
    else
        printf "%s\n" "$test_case" | ./ft_ssl base64 -d 2>>failed_test_log.txt 1>self_test_result.txt
        self_exit_code=$?
    fi

	# OpenSSL output
	printf "%s\n" "$test_case" | openssl base64 -d >openssl_test_result.txt 2>/dev/null

	# Check own program error
	if [ $self_exit_code -eq 1 ]
	then
		echo "Self reported error on test $test_n, $1 (input: $test_case) (Original $2)" >> failed_test_log.txt
		bad_execution=1
	fi

	# Check mem. error
	if [ $self_exit_code -eq 20 ]
	then
		echo "Memory error on test $test_n, $1 (input: $test_case) (Original $2)" >> failed_test_log.txt
		bad_execution=1
	fi

	# Check differences between outputs
	if ! diff self_test_result.txt openssl_test_result.txt > /dev/null; then
		echo "Input difference on $test_n, $1 (input: $test_case) (Original $2):" >> failed_test_log.txt
		echo "self: " >> failed_test_log.txt
		cat  self_test_result.txt >> failed_test_log.txt
		echo "openssl: " >> failed_test_log.txt
		cat openssl_test_result.txt >> failed_test_log.txt
		echo "FAILED: BASE64: Test $test_n, $1. Decode."
		((failed++))
	fi

	rm openssl_test_result.txt self_test_result.txt
}
 
rm -f failed_test_log.txt test_logs.txt

# string tests
testAgainstOpenssl "Empty string" ""
testAgainstOpenssl "Hello world" "Hello, world!"
testAgainstOpenssl "Single char" "S"
testAgainstOpenssl "Single char" "W"
testAgainstOpenssl "Single char" "O"
testAgainstOpenssl "Single char" "P"
testAgainstOpenssl "Single char" "1"
testAgainstOpenssl "Single char" "2"
testAgainstOpenssl "Single char" "3"

# Randomized tests
for i in $(seq 1 $num_random_tests); do
	str_len=$((RANDOM % $random_test_max_length))
	if [ "$1" == "-b" ]; then
		random_str=$(head /dev/urandom | head -c $str_len)
	elif [ "$1" == "-s" ]; then
		random_str=$(head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c $str_len)
	fi
	testAgainstOpenssl "Random string of length $str_len" "$random_str"
done

# Text feedback
echo "----- BASE64 tester -----"
echo "$test_n tests ran. $failed tests failed."
if [ $bad_execution -eq 1 ]
then
	echo "Warning: A memory or self reported error has been found, regardless of OpenSSL output."
fi
echo "Check tests made on base64_test_logs.txt"
echo "Check test failed on failed_test_log.txt"
