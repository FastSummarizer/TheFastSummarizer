# -*- coding: utf-8 -*-
"""
Created on Mon Feb 21 22:57:40 2022

@author: Lucas Prutki
"""

#--------------------------------- PACKAGES ----------------------------------
from hashlib import sha256

from networkx import from_numpy_array, pagerank

import nltk
from nltk.cluster.util import cosine_distance
from nltk.corpus import stopwords

import numpy as np

from PIL import Image

from random import choice, shuffle

from sqlite3 import connect

import streamlit as st

from string import ascii_letters, digits, punctuation

#--------------------------------- FUNCTIONS ---------------------------------
    # Password generator
def generate_random_password(pswd_length=10):
    """
    Function to generate a random password with letters, numbers and special characters.

    Parameters
    ----------
    pswd_length : int, optional
        The password's length, in terms of characters. The default is 10.

    Returns
    -------
    string
        Randomly generated password.

    """
    # Import special characters
    characters = list(ascii_letters + digits + punctuation)

	# Shuffling the characters
    shuffle(characters)
	
	# Picking random characters from the list
    password = []
    for i in range(pswd_length):
        password.append(choice(characters))
    
    # Shuffling the resultant password
    shuffle(password)

	# Converting the list to string
    return "".join(password)


    # Security
def make_hashes(password):
    """
    Function that allows to secure a password with an encryption. SHA fo Secure Hash Algorithm.

    Parameters
    ----------
    password : string
        Password to encrypt.

    Returns
    -------
    string
        Encrypted password.

    """
    return sha256(str.encode(password)).hexdigest()

def check_hashes(password, hashed_text):
    """
    Function that checks if the password given in parameter matches the encrypted 
    password that is stocked. To do this, we use the make_hashes function.

    Parameters
    ----------
    password : string
        Password to verify.
    hashed_text : string
        Encrypted password.

    Returns
    -------
    string or boolean
        Encrypted password if condition is True, else returns False.

    """
    if make_hashes(password) == hashed_text:
        return hashed_text
    return False


    # Connection to MogoDB database
conn = connect("data.db", check_same_thread=False)
c = conn.cursor()


    # Data base management
def create_usertable():
    """
    Method that checks if the table exists, and creates it if not.

    Returns
    -------
    None.

    """
    c.execute("CREATE TABLE IF NOT EXISTS userstable(username TEXT, password TEXT, question TEXT, answer TEXT)")

def add_userdata(username, password, question, answer):
    """
    Method that allows to add a user by a couple (username, password) that 
    will be stored in the table.

    Parameters
    ----------
    username : string
        User's username.
    password : string
        User's password.
    question : string
        Security question chosen by the user.
    answer : string
        User's answer to the security question.

    Returns
    -------
    None.

    """
    c.execute("INSERT INTO userstable(username, password, question, answer) VALUES (?, ?, ?, ?)", (username, password, question, answer))
    conn.commit()

def login_user(username, password):
    """
    Function that checks if the username and password are in the database and 
    allows identification.

    Parameters
    ----------
    username : string
        User's username.
    password : string
        User's password.

    Returns
    -------
    data : tuple
        Result of the query as a tuple, the tuples are empty if there is no 
        match in the table.

    """
    c.execute("SELECT * FROM userstable WHERE username =? AND password =?", (username, password))
    data = c.fetchall()
    return data

def view_all_users():
    """
    Function to query the database and retrieve the list of usernames and 
    encrypted passwords

    Returns
    -------
    data : list of tuples
        Result of the query as a tuple, (username, password).

    """
    c.execute("SELECT * FROM userstable")
    data = c.fetchall()
    return data

def reset_pswd(username, password):
    """
    Method to change / update a password in the database.

    Parameters
    ----------
    username : string
        User's username.
    password : string
        User's password.

    Returns
    -------
    None.

    """
    c.execute("UPDATE userstable SET password =? WHERE username =?", (password, username))
    conn.commit()

def forgot_pswd(username, question, answer):
    """
    Method to change / update a password in the database.

    Parameters
    ----------
    username : string
        User's username.
    question : string
        Security question chosen by the user.
    answer : string
        User's answer to the security question.

    Returns
    -------
    None.

    """
    c.execute("SELECT * FROM userstable WHERE username =? AND question =? AND answer =?", (username, question, answer))
    data = c.fetchall()
    return data

def delete_user(username, password):
    """
    Function that allows you to delete a user from the database.

    Parameters
    ----------
    username : string
        User's username.
    password : string
        User's password.

    Returns
    -------
    None.

    """
    c.execute("DELETE FROM userstable WHERE username =? AND password =?", (username, password))
    conn.commit()


    # App functionnalities
def log_out():
    """
    Method that allows to change the state of an element of a Streamlit class.
    For logout functionality.

    Returns
    -------
    None.

    """
    st.session_state.LoggedIn = False
    st.session_state.LoggedOut = False
    
def log_error():
    """
    Method that allows to change the state of an element of a Streamlit class.
    For login failure functionality.
    
    Returns
    -------
    None.

    """
    st.session_state.LoggedIn = False
    st.session_state.LoggedTry = False
    
def log_reset():
    """
    Method that allows to change the state of an element of a Streamlit class.
    For reset password functionality.

    Returns
    -------
    None.

    """
    st.session_state.ResetedCheck = False
    st.session_state.ResetPswd = False
    st.session_state.LoggedIn = False

def log_reset_error():
    """
    Method that allows to change the state of an element of a Streamlit class.
    For password reset failure functionality.

    Returns
    -------
    None.

    """
    st.session_state.ResetedRetry = False
    st.session_state.ResetedCheck = False

def log_delete():
    """
    Method that allows to change the state of an element of a Streamlit class.
    For delete account functionality.

    Returns
    -------
    None.

    """
    st.session_state.DeletedCheck = False
    st.session_state.DeletedAccount = False
    st.session_state.LoggedIn = False
    
def log_delete_error():
    """
    Method that allows to change the state of an element of a Streamlit class.
    For delete account failure functionality.

    Returns
    -------
    None.

    """
    st.session_state.DeletedRetry = False
    st.session_state.DeletedCheck = False

def log_forgot():
    """
    Method that allows to change the state of an element of a Streamlit class.
    For forgotten password functionality.

    Returns
    -------
    None.

    """
    st.session_state.ValidatedCheck = False
    st.session_state.ForgottenCheck = False
    
def log_forgot_error():
    """
    Method that allows to change the state of an element of a Streamlit class.
    For forgotten password failure functionality.

    Returns
    -------
    None.

    """
    st.session_state.ForgottenTry = False
    st.session_state.ValidatedCheck = False

def forgot_password():
    """
    Method that allows a user to reset his password from his login and the 
    answer to a security question given when he created his account. A new 
    random password is given to him and is updated in the database.

    Returns
    -------
    None.

    """
    # User ID
    user = st.empty()
    username = user.text_input("User Name", key=30)
    
    # User informations
    question = st.selectbox("Question",["What is your favorite color?",
                                        "What was the name of your school?",
                                        "In which city did you grow up?"])
    answr = st.empty()
    answer = answr.text_input("Answer", key=31)
    
    # Callback
    validated_check = st.checkbox(label="Validate", 
                                  key="ValidatedCheck"
                                  )
    
    if validated_check:
        # ID verification
        create_usertable()
        result = forgot_pswd(username, question, answer)
        
        if result:
            # New password generator
            new_password = generate_random_password()
            
            col1, col2 = st.columns(2)
            
            col1.markdown("New password:")
            code = f"{new_password}"
            col2.code(code, language="python")
            
            # Reset password in database
            reset_pswd(username, make_hashes(new_password))
            
            # Task validated
            st.success("✔️ Your password has been reseted.")
            
            # Redirection button
            st.button("👉 Go to LogIn menu", on_click=log_forgot)
            
        else:
            # Reset text area
            username = user.text_input("User Name", value="", key=32)
            answer = answr.text_input("Answer", value="", key=33)
            
            # Information message
            st.error("❌ Incorrect Username/Question/Answer. Please retry.")
            
            with st.sidebar:
                col1, col2, col3 = st.columns(3)
                
                # Callback
                forgotten_retry = col3.checkbox(label="Retry", 
                                                 key="ForgottenTry", 
                                                 on_change=log_forgot_error)
                
def reset_password():
    """
    Method that allows a user to change their password and update the new 
    password in the database.

    Returns
    -------
    None.

    """
    # User ID
    user = st.empty()
    username = user.text_input("User Name", key=5)
    
    # User passeword
    old_pswd = st.empty()
    old_password = old_pswd.text_input("Old password", type="password", key=6)
    new_pswd = st.empty()
    new_password = new_pswd.text_input("New password", type="password", key=7)
    
    # Callback
    reseted_check = st.checkbox(label="Reset", 
                                key="ResetedCheck",
                                #on_change=log_reset
                                )
    
    if reseted_check:
        # ID verification
        create_usertable()
        hashed_pswd = make_hashes(old_password)
        result = login_user(username, check_hashes(old_password, hashed_pswd))
        
        if result:
            st.success("✔️ Logged In, password being re-initialized.")
            reset_pswd(username, make_hashes(new_password))
            
            # Reset text area
            username = user.text_input("User Name", value="", key=8)
            old_password = old_pswd.text_input("Old password", value="", key=9)
            new_password = new_pswd.text_input("New password", type="password", key=10)
            
            # Task validated
            st.success("✔️ Your passeword has been re-initialized.")
            
            # Information message
            st.info("Please LogIn with your new password. 🔐")
            
            # Redirection button
            st.button("👉 Go to LogIn menu", on_click=log_reset)
            
        else:
            # Reset text area
            username = user.text_input("User Name", value="", key=11)
            old_password = old_pswd.text_input("Old password", value="", key=12)
            new_password = new_pswd.text_input("New password", type="password", key=13)
            
            # Task failed
            st.error("❌ Incorrect Username/Password. Please retry.")
            
            # Callback
            reseted_retry = st.checkbox(label="Retry", 
                                        key="ResetedRetry", 
                                        on_change=log_reset_error)


def delete_account():
    """
    Method that allows a user to delete his account from the database.

    Returns
    -------
    None.

    """
    # User ID
    user = st.empty()
    username = user.text_input("User Name", key=14)
    
    # User passeword
    pswd = st.empty()
    password = pswd.text_input("Password", type="password", key=15)
    
    # Callback
    deleted_check = st.checkbox(label="Delete", 
                                key="DeletedCheck",
                                #on_change=log_delete
                                )

    if deleted_check:
        # ID verification
        create_usertable()
        hashed_pswd = make_hashes(password)
        result = login_user(username, check_hashes(password, hashed_pswd))
        
        if result:
            st.success("✔️ Logged In, account being deleted.")
            delete_user(username, make_hashes(password))
            
            # Reset text area
            username = user.text_input("User Name", value="", key=16)
            password = pswd.text_input("Password", value="", key=17)
            
            # Task validated
            st.success("✔️ Your account has been deleted.")
            
            # Information message
            st.info("Your account has been deleted. Se you next time! 👋")
            
        else:
            # Reset text area
            username = user.text_input("User Name", value="", key=18)
            password = pswd.text_input("Password", value="", key=19)
            
            # Task failed
            st.error("❌ Incorrect Username/Password. Please retry.")
            
            # Callback
            reseted_retry = st.checkbox(label="Retry", 
                                        key="DeletedRetry", 
                                        on_change=log_delete_error)


    # App functions
def read_article(uploaded_file):
    """
    Function that reads a text file and returns a list of clean sentences.
    
    Parameters
    ----------
    uploaded_file : Streamlit object
        The uploaded file from Streamlit webapp.

    Returns
    -------
    sentences : list
        List of clean sentences.

    """ 
    filedata = str(uploaded_file.read(), "utf-8")
    article = filedata.split(". ")
    sentences = []
    
    for sentence in article:
        sentences.append(sentence.replace("[^a-zA-Z]", " ").split(" "))
    sentences.pop()
    
    return sentences


def sentence_similarity(sent1, sent2, stopwords=None):
    """
    A function that calculates the similarity between sentences in a text with 
    cosine similarity. It returns a similarity measure.

    Parameters
    ----------
    sent1 : string
        First sentence with which we will calculate the similarity.
    sent2 : string
        Second sentence with which we will calculate the similarity.
    stopwords : list, optional
        The default is None.

    Returns
    -------
    float
        The similarity measure with cosine similarity.

    """
    if stopwords is None:
        stopwords = []
 
    sent1 = [w.lower() for w in sent1]
    sent2 = [w.lower() for w in sent2]
 
    all_words = list(set(sent1 + sent2))
 
    vector1 = [0] * len(all_words)
    vector2 = [0] * len(all_words)
 
    # build the vector for the first sentence
    for w in sent1:
        if w in stopwords:
            continue
        vector1[all_words.index(w)] += 1
 
    # build the vector for the second sentence
    for w in sent2:
        if w in stopwords:
            continue
        vector2[all_words.index(w)] += 1
 
    return 1 - cosine_distance(vector1, vector2)
 
def build_similarity_matrix(sentences, stop_words):
    """
    Function to retrieve the similarity measures between two sentences and put 
    them in a matrix.

    Parameters
    ----------
    sentences : list
        List of clean sentences.
    stop_words : list
        List of stopwords.

    Returns
    -------
    similarity_matrix : np.array
        Similarity matrix.

    """
    # Create an empty similarity matrix
    similarity_matrix = np.zeros((len(sentences), len(sentences)))
 
    for idx1 in range(len(sentences)):
        for idx2 in range(len(sentences)):
            if idx1 == idx2: #ignore if both are same sentences
                continue 
            similarity_matrix[idx1][idx2] = sentence_similarity(sentences[idx1], sentences[idx2], stop_words)

    return similarity_matrix


def generate_summary(uploaded_file, top_n):
    """
    This method will call all the other functions to keep our summarization 
    pipeline running. It takes 4 steps: 
        1) Read the text file and cut out all the sentences read_article();
        2) Compute the cosine similarity measure between sentences with the 
           sentence_similarity() function;
        3) Generate a similarity matrix between sentences with the 
           build_similarity_matrix() function;
        4) Sort the sentences by order of importance and display the text 
           summary with the generate_summary() function.

    Parameters
    ----------
    uploaded_file : Streamlit object
        The uploaded file from Streamlit webapp.
    top_n : int
        Number of sentences to display in the summary.

    Returns
    -------
    summarized_text : string
        Summarized text.

    """
    nltk.download("stopwords")
    stop_words = stopwords.words('english')
    summarize_text = []

    # Step 1 - Read text anc split it
    sentences =  read_article(uploaded_file)

    # Step 2 - Generate Similary Martix across sentences
    sentence_similarity_martix = build_similarity_matrix(sentences, stop_words)

    # Step 3 - Rank sentences in similarity martix
    sentence_similarity_graph = from_numpy_array(sentence_similarity_martix)
    scores = pagerank(sentence_similarity_graph)

    # Step 4 - Sort the rank and pick top sentences
    ranked_sentence = sorted(((scores[i],s) for i,s in enumerate(sentences)), reverse=True)    
    #print("Indexes of top ranked_sentence order are ", ranked_sentence)    

    for i in range(top_n):
	summarize_text.append(" ".join(ranked_sentence[i][1]))
      #summarize_text.append(" ".join(ranked_sentence[i][1]))
    
    # Add a . at the end of the summary
    summarize_text.append(" ")
    
    # Step 5 - Offcourse, output the summarize text
    #print("Summarize Text: \n", ". ".join(summarize_text))
    summarized_text = ". ".join(summarize_text)
    
    return summarized_text


    # App
#---------------------------------- SQLITE 3 -----------------------------
    # Connection to MogoDB database
conn = connect("data.db", check_same_thread=False)
c = conn.cursor()

#------------------------------- PAGE SETTINGS ---------------------------
image = Image.open("logoAI.png")

st.set_page_config(
     page_title="The FastSummarizer - AI",
     page_icon=image,
     layout="wide",
     initial_sidebar_state="expanded",
     menu_items={
         "Get help": "https://github.com/lprtk/text-summarizer",
         "Report a bug": "https://github.com/lprtk/text-summarizer/issues",
         "About": "Hi, welcome on my App! If you have a bug or anythings that which prevents you from use the functionalities of the App, please report it to my GitHub page."
     }
)

#------------------------------- DESIGN / CODE ---------------------------
col1, col2 = st.columns(2)
col1.image(image, width=230)
col2.subheader(
    "Group CDO MoSEF \n"
    "Strategic Needs Artificial Intelligence"
    )

st.markdown(
    """
    <h1 style='text-align: center'>
        <font color='#FFFFFF'>
            The FastSummarizer
        </font>
    </h1>
    """, True
    )

st.markdown(
    """
    <h2 style='font-family: Arial'>
        <font color='#FFFFFF'>
            🤖💬 Hi!
        </font>
    </h2>
    """, True
    )

st.markdown(
    """
    <h4 style='text-align: justify'>
        <font color= '#FFFFFF'>
            Don't you want to read? Don't worry, I'm like you! Welcome to this application 
            that will allow you to stop reading. Enter a text and I will give you a summary 
            of it.
        </font>
    </h4>
    """, True
    )

st.markdown("<br/>", True)

st.markdown(
    """
    <h4 style='text-align: center'>
        <font color='#FFFFFF'>
            Like you, many people don't want to read anymore! *
        </font>
    </h4>
    """, True
    )

col1, col2, col3, col4 = st.columns(4)
col2.metric("Last week's attendance", "82%", "26.8%")
col3.metric("Number of texts summarized", "727", "14%")
col4.metric("Customer satisfaction", "92%", "5%")
st.markdown(
    """
    <p>
        <font color='#FFFFFF'>
            *compared to last week's activity
        </font>
    </p>
    """, True
    )

st.markdown("<br/>", True)

#-------------------------------- APP CONTENT ----------------------------
menu = ["Home", "LogIn", "SignUp"]

st.sidebar.markdown(
    """
    <h4>
        <font color='#FFFFFF'>
            Connexion 🔒
        </font>
    </h4>
    """, True
    )

choice = st.sidebar.selectbox("Menu", menu)

col1, col2, col3 = st.columns(3)

if choice == "Home":
    st.markdown(
        """
        <h2 style='font-family: Arial'>
            <font color='#FFFFFF'>
                Home
            </font>
        </h2>
        """, True
        )

    st.markdown(
        """
        <h4>
            <font color='#FFFFFF'>
                About the App 🔎
            </font>
        </h4>
        """, True
        )
    
    with st.expander("About"):
        st.markdown(
            """
            <p>
                <font color='#FFFFFF'>
                    Do you want to quickly summarize a text? Use The FastSummarizer 
                    to help you on a daily basis. Log in, import your file, select 
                    the length of your summary and download it!
                </font>
            </p>
            """, True
            )
            
    with st.sidebar:
        st.info(
            """
            ☝ Please use the menu above to authenticate yourself before using the App.
            """
            )

elif choice == "LogIn":
    st.markdown(
        """
        <h2 style='font-family: Arial'>
            <font color='#FFFFFF'>
                LogIn Section 🔐
            </font>
        </h2>
        """, True
        )
    
    with st.sidebar:
        # User ID
        user = st.empty()
        username = user.text_input("User Name", key=1)
        
        # User passeword
        pswd = st.sidebar.empty()
        password = pswd.text_input("Password", type="password", key=2)
        
        # Callback
        col1, col2, col3 = st.columns(3)
        
        loggedin_check = col1.checkbox(label="LogIn", 
                                       key="LoggedIn")
        
        if not loggedin_check:
            forgotten_check = col3.checkbox(label="Forgot password", 
                                            key="ForgottenCheck")
            
            if forgotten_check:
                st.markdown("<br/>", True)
                
                st.markdown(
                    """
                    <h3 style='font-family: Arial'>
                        <font color='#FFFFFF'>
                            Forgot your password 🔏
                        </font>
                    </h3>
                    """, True
                    )
                
                # Call function
                forgot_password()
    
    if loggedin_check:
        # ID verification
        create_usertable()
        hashed_pswd = make_hashes(password)
        result = login_user(username, check_hashes(password, hashed_pswd))
        
        if result:
            st.success(f"✔️ Hi {username}, you have successfully Logged In!")
            
            # Reset text area
            username = user.text_input("User Name", value="", key=3)
            password = pswd.text_input("Password", value="", key=4)
            
            #-------------------------------------------------------------
            # App content
            
            st.markdown("<br/>", True)
            
            st.markdown(
                """------------------------------------------------------------""", True
                )
            
            
            st.markdown(
                """
                <h2 style='font-family: Arial'>
                    <font color='#FFFFFF'>
                        How to use the application's functionalities:
                    </font>
                </h2>
                <ol>
                    <li>Upload your data: you must load a text file to be summarized in the drag and drop area.</li>
                    <li>Select the length of the summary that the FastSummarizer should make.
                    <li>Download your data: you just have to click on the button to download the summary of your text.</li>
                </ol>
                """, True
                )
            
            st.markdown("<br/>", True)
            
            st.markdown(
                """
                <h3 style='font-family: Arial'>
                    <font color='#FFFFFF'>
                        1. Import a text file
                    </font>
                </h3>
                """, True
                )
            
            st.markdown(
                """
                <p>
                    Choose a text file that you want to summarize 📥.
                </p>
                """, True
                )
            
            upload_file = st.file_uploader("", type=["txt"])
            if upload_file:                
                st.write("● Filename: ", upload_file.name)
                st.write("● Filtype: ", upload_file.type)
                st.write("● Filsize: ", upload_file.size)
                data = upload_file.name
                
                filedata = str(upload_file.read(), "utf-8")
                article = filedata.split(". ")
                sentences = []
                
                for sentence in article:
                    sentences.append(sentence.replace("[^a-zA-Z]", " ").split(" "))
                sentences.pop()
                
                length_file = len(sentences)
                
                st.write("● Number of sentences:", length_file)
                
                st.markdown("<br/>", True)
                st.markdown("<br/>", True)
                
                number_list = []
                for i in range(0, length_file+1, 1):
                    number_list += [str(i)]

                length = number_list
                
                st.markdown(
                    """
                    <h3 style='font-family: Arial'>
                        <font color='#FFFFFF'>
                            2. Select a length for the summary
                        </font>
                    </h3>
                    """, True
                    )
                
                st.markdown(
                    """
                    <p>
                        Select the number of sentences 🛑.
                    </p>
                    """, True
                    )
                
                length_choice = st.selectbox("", length)
                
                length_choice = int(length_choice)
                
                if length_choice > 0:
                    resumed_text = generate_summary(upload_file, length_choice)
                    
                    st.markdown("<br/>", True)
                    st.markdown("<br/>", True)
                    
                    st.success("✔️ Done! You can download the file.")
                    
                    filename = upload_file.name.split(".")
                    
                    st.markdown("<br/>", True)
                    
                    st.markdown(
                        """
                        <h3 style='font-family: Arial'>
                            <font color='#FFFFFF'>
                                3. Download your text file
                            </font>
                        </h3>
                        """, True
                        )
                    
                    st.markdown(
                        """
                        <p>
                            Download the summary text 📤.
                        </p>
                        """, True
                        )
                    
                    st.markdown("<br/>", True)
                    
                    st.download_button(
                        label="Download file 📄",
                        data=resumed_text,
                        file_name=f"{filename[0]}_summarized.txt",
                        mime="text/plain"
                        )
                
            #-------------------------------------------------------------
            
            # LogOut configuration
            loggedout_check = col3.checkbox(label="LogOut", 
                                            key="LoggedOut",
                                            on_change=log_out)
            
            with st.sidebar:
                st.sidebar.markdown("<br/>", True) 
                col1, col2 = st.columns(2)
            
                # Reset password configuration
                resetpswd_check = col1.checkbox(label="Reset password", 
                                                key="ResetPswd")
            
            with st.sidebar:
                col1, col2 = st.columns(2)
            
                # Delete account configuration
                deleteaccount_check = col1.checkbox(label="Delete account", 
                                                    key="DeletedAccount")
            
            # LogOut process
            if loggedout_check:
                st.warning("Disconnect, see you soon! 👋")
                
            # Reset password process
            if resetpswd_check:
                with st.sidebar:
                    st.markdown("<br/>", True)
                    
                    st.markdown(
                        """
                        <h3 style='font-family: Arial'>
                            <font color='#FFFFFF'>
                                Reset your password 🔏
                            </font>
                        </h3>
                        """, True
                        )
                
                    # Call function
                    reset_password()
                
            # Delete account process
            if deleteaccount_check:
                with st.sidebar:
                    st.markdown("<br/>", True)
                    
                    st.markdown(
                        """
                        <h3 style='font-family: Arial'>
                            <font color='#FFFFFF'>
                                Delete your account 🔒
                            </font>
                        </h3>
                        """, True
                        )

                    # Call function
                    delete_account()
                
        else:
            # Reset text area
            username = user.text_input("User Name", value="", key=20)
            password = pswd.text_input("Password", value="", key=21)
            
            # Information message
            st.error("❌ Incorrect Username/Password. Please retry.")
            
            with st.sidebar:
                col1, col2, col3 = st.columns(3)
                
                # Callback
                loggedin_retry = col3.checkbox(label="Retry", 
                                               key="LoggedTry", 
                                               on_change=log_error)
    else:
        st.info(
            """
            👈 Please use the menu in the left side to authenticate yourself before using the App.
            """
            )

elif choice == "SignUp":
    st.markdown(
        """
        <h2 style='font-family: Arial'>
            <font color='#FFFFFF'>
                Create New Account 👀
            </font>
        </h2>
        """, True
        )

    st.info(
        """
        Welcome on our App! 👋 You are not already register, create your account to use our analytics tools.
        """
        )
            
    new_user = st.text_input("User Name")
    question = st.selectbox("Question",["What is your favorite color?",
                                        "What was the name of your school?",
                                        "In which city did you grow up?"])
    answer = st.text_input("Answer")
    new_password = st.text_input("Password", type="password")
    
    st.sidebar.markdown(
        """
        <h4>
            <font color='#FFFFFF'>
                About the App 🔎
            </font>
        </h4>
        """, True
        )
    
    with st.sidebar.expander("About"):
        st.markdown(
            """
            <p>
                <font color='#FFFFFF'>
                    Do you want to quickly summarize a text? Use The 
                    FastSummarizer to help you on a daily basis. Log in, 
                    import your file, select the length of your summary 
                    and download it!
                </font>
            </p>
            """, True
            )
    
    if st.button("SignUp"):
        create_usertable()
        add_userdata(new_user, make_hashes(new_password), question, answer)
        st.success("✔️ You have successfully created a valid account!")
        st.info("Go to LogIn Menu to login. 🔐")

#---------------------------------- SQLITE 3 -----------------------------
    # Close the database
conn.commit()
c.close()
