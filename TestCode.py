This is a test code

from itertools import combinations

'GITHUB_TOKEN = 'ghp_2pyjwJO4ugcg2dvW4SAJajZcJzZZZS0wypSa'

# Define the patterns (this can be expanded as needed)
patterns = ['887', '997', '998', '878', '788', '979', '799', '989', '899']

# Function to generate numbers in a specified range (inclusive)
def generate_numbers_in_range(start, end):
    return [f"{i:05d}" for i in range(start, end + 1)]

# Function to check if the sum of any two digits matches a pattern
def check_pattern_match(digits, patterns):
    # Convert the digits into a list of integers for easier handling
    digits = [int(d) for d in digits]
    
    # List to hold the sum of pairs
    pair_sums = []
    
    # Create a list to track used digits (initially none are used)
    used = [False] * 5  # We have 5 digits, initially none are used
    
    # Try all unique pairs (combinations) of digits
    for i, j in combinations(range(5), 2):
        if not used[i] and not used[j]:
            # Calculate the sum of the pair
            pair_sum = digits[i] + digits[j]
            
            # Add this sum to the list of pair sums
            pair_sums.append(pair_sum)
            
            # Mark these digits as used
            used[i] = True
            used[j] = True
    
    # Sort pair sums and check if they match any pattern
    pair_sums.sort()
    
    for pattern in patterns:
        # Convert the pattern to a sorted list of integers
        pattern_sums = sorted([int(x) for x in pattern])
        
        # If the sorted pair sums match the pattern sums
        if pair_sums == pattern_sums:
            return pattern
    return None

# Function to find valid numbers in a specified range
def find_matching_numbers_in_range(start, end):
    valid_numbers = []
    
    # Generate numbers within the specified range
    for number in generate_numbers_in_range(start, end):
        # Check if any of the sums match a pattern
        pattern = check_pattern_match(number, patterns)
        
        if pattern:
            valid_numbers.append(f"{number} - {pattern}")
    
    return valid_numbers

# Function to find matching numbers without multithreading and print them
def find_matching_numbers(start_range, end_range, output_file):
    valid_numbers = find_matching_numbers_in_range(start_range, end_range)
    print(f"opening file {output_file} to write.")
    # Write all valid numbers to the output file
    with open(output_file, 'w') as f:
        for valid_number in valid_numbers:
            f.write(valid_number + '\n')

# Example usage: specify the range for 5-digit numbers (e.g., 10000 to 99999)
start_range = 10000  # Starting number (inclusive)
end_range = 99999    # Ending number (inclusive)
output_file = "valid_numbers.txt"  # Output file name

print(f"Start Range: {start_range} & End Range: {end_range}")
# Run the program without multithreading and write results to a file
find_matching_numbers(start_range, end_range, output_file)

print(f"Valid numbers have been written to {output_file}.")