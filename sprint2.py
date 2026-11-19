import streamlit as st

st.title("Test Streamlit App")
name = st.text_input("Enter your name")

if name:
    st.success(f"Hello, {name}!")

print("Hello ninteenth of november twenty twenty six")
# comment

x = 0

x = int(input("enter a number: "))

if (x < 10):
    print("the number is less than ten.")

else:
    print("the number is greater than ten.")




