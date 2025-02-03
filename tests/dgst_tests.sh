#!/bin/bash

if [ -z "$1" ] || { [ "$1" != "-b" ] && [ "$1" != "-s" ]; }; then
    echo "DGST Tester."
	echo "bash dgst_tests.sh [-s|-b] [-m] "
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
function testAgainstOpenssl() {
	((test_n++))

	echo "$algorithm: Test $test_n, $1 (input: $2)" >> test_logs.txt
	echo "$algorithm: Test $test_n, $1"

	self_command=${algorithm_map[$algorithm]}
	openssl_command=$algorithm

	# Own test (With or without valgrind)
    if $memory_test_flag; then
        printf "%s" "$2" | valgrind --log-file=/dev/null --error-exitcode=20 --track-fds=yes --leak-check=full --show-leak-kinds=all ./ft_ssl $self_command -q 2>/dev/null 1>self_test_result.txt
        self_exit_code=$?
    else
        printf "%s" "$2" | ./ft_ssl $self_command -q 2>/dev/null 1>self_test_result.txt
        self_exit_code=$?
    fi

	# dgst test
	if [ "$algorithm" == "whirlpool" ]; then 
		printf "%s" "$2" | openssl $openssl_command -r -provider legacy| cut -d ' ' -f 1 >openssl_test_result.txt
    else
		printf "%s" "$2" | openssl $openssl_command -r | cut -d ' ' -f 1 >openssl_test_result.txt
    fi
	

	# Check mem. error
	if [ $self_exit_code -eq 20 ]
	then
		echo "$algorithm: Memory error on test $test_n, $1 (input: $2)" >> failed_test_log.txt
		bad_execution=1
	fi

	# Check own program error
	if [ $self_exit_code -eq 1 ]
	then
		echo "$algorithm: Self reported error on test $test_n, $1 (input: $2)" >> failed_test_log.txt
		bad_execution=1
	fi

	# Check differences between outputs
	if ! diff self_test_result.txt openssl_test_result.txt > /dev/null; then
		echo "$algorithm: Input difference on $test_n, $1 (input: $2):" >> failed_test_log.txt
		cat self_test_result.txt >> failed_test_log.txt
		cat openssl_test_result.txt >> failed_test_log.txt

		echo "FAILED: $algorithm: Test $test_n, $1."
		((failed++))
	fi

	rm openssl_test_result.txt self_test_result.txt
}

rm -f failed_test_log.txt test_logs.txt

algorithms=("whirlpool" "sha224" "sha256" "sha384" "sha512" "sha512-256" "sha512-224")
declare -A algorithm_map
algorithm_map["whirlpool"]="WHIRLPOOL"
algorithm_map["sha224"]="SHA-224"
algorithm_map["sha256"]="SHA-256"
algorithm_map["sha384"]="SHA-384"
algorithm_map["sha512"]="SHA-512"
algorithm_map["sha512-256"]="SHA-512/256"
algorithm_map["sha512-224"]="SHA-512/224"

for algorithm in "${algorithms[@]}"; do
	# string tests
	testAgainstOpenssl "Empty string" ""
	testAgainstOpenssl "Hello world" "Hello, world!"

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
done

# Text feedback
echo "----- Digest tester -----"
echo "$test_n tests ran. $failed tests failed."
if [ $bad_execution -eq 1 ]
then
	echo "Warning: A memory or self reported error has been found, regardless of openssl output."
fi
echo "Check tests made on test_logs.txt"
echo "Check test failed on failed_test_log.txt"
