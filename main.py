import os
import math
import psutil
import platform

cpu_type = platform.processor()

special_chars = set(r"\!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~")
pw = input("\nEnter password: ")
pw_len = len(pw)
lowercase_found = 0
uppercase_found = 0

#Functions for password analysis.
def pw_length_analysis(password):
    if pw_len < 12:
        return False
    else:
        return True
    
#Function to analyze special characters in the password.
def pw_special_char_analysis(password):
    special_chars_found = 0
    for char in password:
        if char in special_chars:
            special_chars_found += 1
    return special_chars_found

#Function to count uppercase and lowercase letters in the password.
def pw_case_counter(password):
    lowercase_found = 0
    uppercase_found = 0
    for char in password:
        if char.islower():
            lowercase_found += 1
    for char in password:
        if char.isupper():
            uppercase_found += 1
    return lowercase_found, uppercase_found    

#Function to analyze case usage in the password.
def pw_case_analysis(password):
    lower, upper = pw_case_counter(password)
    if lower > 0 and upper > 0:
        return "Password has a mix of uppercase and lowercase letters"
    elif lower > 0 and upper == 0:
        return "Password has only lowercase letters"
    elif lower == 0 and upper > 0:
        return "Password has only uppercase letters"

#Function to analyze repeating characters in the password.
def repeat_char_analysis(password):
    times_char_seen = {}
    for char in password:
        if char in times_char_seen:
            times_char_seen[char] += 1
        else:
            times_char_seen[char] = 1
    return times_char_seen

def pw_feedback(password):
    feedback = []
    negative_instances = 0
    #Uppercase found feedback.
    if uppercase_found < (pw_len / 5):
        feedback.append("Consider adding more uppercase letters to your password.")
        negative_instances += 1
    else:
        feedback.append("You have a good amount of uppercase letters in your password.")

    #Lowercase found feedback.
    if lowercase_found < (pw_len / 5):
        feedback.append("Consider adding more lowercase letters to your password.")
        negative_instances += 1
    else:
        feedback.append("You have a good amount of lowercase letters in your password.")

    #Special characters feedback.
    if pw_special_char_analysis(password) == 0:
        feedback.append("Consider adding special characters to your password.")
        negative_instances += 2
    elif pw_special_char_analysis(password) < 2:
        feedback.append("You have some special characters, consider adding more for better security.")
        negative_instances += 1
    else:
        feedback.append("You have a good amount of special characters in your password.")

    #Password length feedback.
    if pw_len < 4:
        feedback.append("Your password is extremely short. It is highly recommended to make it at least 12 characters long.")
        negative_instances += 10
    elif pw_len < 8:
        feedback.append("Your password is quite short. You should make it at least 12 characters long.")
        negative_instances += 5
    elif pw_len < 12:
        feedback.append("Your password length is decent, but consider making it longer for better security.")
        negative_instances += 3
    else:
        feedback.append("Your password length is good. Adding more characters can further enhance security.")
    
    #Character repetition feedback.
    if repeat_char_analysis(password):

        for char in repeat_char_analysis(password):
            if repeat_char_analysis(password)[char] > 5:
                feedback.append(f"Character '{char} is repeated {repeat_char_analysis(password)[char]} times. You should reduce the repetition of {char} in your password.")
                negative_instances += 3
            elif repeat_char_analysis(password)[char] > 2:
                feedback.append(f"Character '{char}' is repeated {repeat_char_analysis(password)[char]} times. Consider reducing the repetition of {char} in your password.")
                negative_instances += 1
            elif repeat_char_analysis(password) == {}:
                feedback.append("No repeating characters found in your password. Good job!")

    #Overall feedback based on negative instance rating system.
    if negative_instances == 0:
        rating = ("Overall, your password is strong and well-constructed. Keep up the good work!")
    elif negative_instances >= 4:
        rating = ("Your password is decent but there are several areas that need improvement. Consider the feedback provided to enhance its security.")
    elif negative_instances >= 7:
        rating = ("Your password is okay but could benefit from some improvements. Review the feedback to strengthen it.")
    elif negative_instances >= 10:
        rating = ("Your password has multiple weaknesses. It's highly recommended to follow the feedback closely to create a more secure password.")
    else:
        rating = ("Please go through the feedback and make necessary improvements to increase your password safety. ")

    return feedback, rating

def entropy_analysis(password):
    pool_size = 94 #The pool size is 26 lowercase + 26 uppercase + 10 digits + 32 special characters (approximate) because of the full ASCII printable set.
    entropy = len(password) * math.log2(pool_size) 
    return entropy    

#Function to estimate time to crack password based on CPU speed.
def cpu_speed():
    cpu_speed_mhz = psutil.cpu_freq().current
    total_combinations = 2**entropy_analysis(pw)
    time = total_combinations / cpu_speed_mhz
    return time, cpu_speed_mhz

#Output the analysis results.
amount_lower, amount_upper = pw_case_counter(pw)

print("\n__________________________ Password Analysis Report __________________________")
if pw_special_char_analysis(pw):
    print(f"Password contains {pw_special_char_analysis(pw)} special characters.")

if amount_lower > 0:
    print(f"Amount of lowercase letters: {amount_lower}")
if amount_upper > 0:
    print(f"Amount of uppercase letters: {amount_upper}")
if amount_lower == 0 and amount_upper == 0:
    print("No alphabetic characters found in the password.")

#Characters are stored in a set of 8 bits or a byte, although they only use 7 out of the 8 bits.
print(f"Entropy of the password: {round(entropy_analysis(pw), 2)} bits or {round(entropy_analysis(pw) / 8, 2)} bytes.")
print(f"Entropy is calculated based on the assumption of a full ASCII printable character set. The forumla used is:\n - Entropy = Length of password * log2(pool size)")
print(f"The password is {pw_len} characters long and the pool size is approximated to be 94 characters (26 lowercase + 26 uppercase + 10 digits + 32 special characters).")
attack = input("Would you like to run an attack simulation on this password? (y/n) ")

#Attack simulation output.
if attack.lower() == "y":
    time, cpu_speed_mhz = cpu_speed()
    print("\n__________________________ Brute Force Attack Simulation Report __________________________")
    print(f"Your CPU type is: {cpu_type} running at {cpu_speed_mhz:,} MHz.")
    print(f"Estimated time to crack password with CPU:\n - {time:,.3} seconds.\n - {time/60:,.3} minutes.\n - {time/3600:,.3} hours.\n - {time/86400:,.3} days.\n - {time/31536000:,.3} years.")
    pw_feedback_list = pw_feedback(pw)
    print("__________________________ Password Improvement Feedback __________________________")
    for feedback in pw_feedback_list[0]:
        print(f"- {feedback}")
    print(pw_feedback_list[1])
    print("Exiting the program...\n")
    os._exit(0)
else:
    pw_feedback_list = pw_feedback(pw)
    print("\n__________________________ Password Improvement Feedback __________________________")
    for feedback in pw_feedback_list[0]:
        print(f"- {feedback}")
    print(pw_feedback_list[1])
    if attack.lower() != "n":
        print("Invalid input.")
    print("Exiting the program...\n")
    os._exit(0)