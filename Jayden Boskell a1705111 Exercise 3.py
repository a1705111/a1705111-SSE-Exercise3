#!/usr/bin/env python
# coding: utf-8

# In[1]:


# Import required packages. 
import os
# Set the git executable location. If you are running this script, make sure you set this to be where git is 
# on your computer (My git is in an odd place due to the way my computer is set up!)
os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = "D:\Program Files\Git\cmd\git.exe"
import git
import datetime
import time


# In[2]:


# Remote links to the github repositories.
remote_link_rest = 'https://github.com/spring-projects/spring-data-rest'
remote_link_camel = 'https://github.com/apache/camel'
remote_link_struts = 'https://github.com/apache/struts'

# Local links to the github repository clones. 
local_link_rest = "repo/rest"
local_link_camel = "repo/camel"
local_link_struts = "repo/struts"


# In[3]:


# Fixing commit and important files in that commit for the rest repository.
rest_fixing_commit = '8f269e28fe8038a6c60f31a1c36cfda04795ab45'
rest_files = ['spring-data-rest-webmvc/src/main/java/org/springframework/data/rest/webmvc/json/patch/AddOperation.java',
        'spring-data-rest-webmvc/src/main/java/org/springframework/data/rest/webmvc/json/patch/PatchOperation.java',
        'spring-data-rest-webmvc/src/test/java/org/springframework/data/rest/webmvc/json/patch/JsonPatchTests.java',
        'spring-data-rest-webmvc/src/test/resources/org/springframework/data/rest/webmvc/json/patch/patch-invalid-path.json']

# Fixing commit and important files in that commit for the camel repository.
camel_fixing_commit = 'adc06a78f04c8d798709a5818104abe5a8ae4b38'
camel_files = ['camel-core/src/main/java/org/apache/camel/model/dataformat/CastorDataFormat.java',
              'components/camel-castor/src/main/java/org/apache/camel/dataformat/castor/AbstractCastorDataFormat.java',
              'components/camel-castor/src/main/java/org/apache/camel/dataformat/castor/WhitelistObjectFactory.java',
              'components/camel-castor/src/test/java/org/apache/camel/dataformat/castor/WhitelistTest.java',
              'platforms/spring-boot/components-starter/camel-castor-starter/src/main/java/org/apache/camel/dataformat/castor/springboot/CastorDataFormatConfiguration.java']

# Fixing commit and important files in that commit for the struts repository. 
struts_fixing_commit = 'd7804297e319c7a12245e1b536e565fcea6d650'
struts_files = ['xwork-core/src/main/java/com/opensymphony/xwork2/ognl/SecurityMemberAccess.java']


# In[4]:


# Class for finding vulnerability causing commits. 
class vulnerability_causing_commit_finder:
    # Constructs the object. 
    # target_repo should be a string representing the path to the repository. 
    # flags are additional flags to run with git blame, generally from the list:
    # '', '-w', '-wM', '-wC', '-wCC', '-wCCC'
    def __init__(this, target_repo, flags):
        this.repo = git.Repo(target_repo)
        this.flag = flags
    
    # Returns a dictionary with keys = commits and values = number of lines changed 
    # which blame that commit.
    # Also prints out a similar dictionary showing how many of those blames are from added lines
    # and how many are from deleted lines. 
    # Commit is which commit to consider.
    # Files is a list containing which files to consider. 
    def get_blamed_commits(this, commit, files):
        # Dictionary to hold the blamed commits. 
        blamed_commits = {}
        added_blamed_commits = {}
        removed_blamed_commits = {}
        
        # For each file passed to the function
        for file in files:
            #print(file)
            
            # Performs a diff using the -W flag which causes the diff to show the entire function
            # the changed line is part of as context. 
            # For lines added, the entire function is likely relevant to the vulnerability
            # causing commit, so we want the entire function as what we will blame. 
            diff_full_context = this.repo.git.diff("-W", commit + "~", commit, "--", file)
            
            # Performs a diff using the -UO flag which causes no context to be printed.
            # For lines removed, only the removed lines are relevant to the vulnerability
            # causing commit, so we don't want any context. 
            diff_no_context = this.repo.git.diff("-U0", commit + "~", commit, "--", file)
        
            # Set of line numbers to blame which were added in the commit.
            added_lines = set()
            
            # Set of line numbers to blame which were deleted in the commit.
            removed_lines = set()
        
            # For each line in the full context diff
            for line in diff_full_context.splitlines():
                # Skip anything which is not a hunk header. 
                if not line.startswith('@@'):
                    continue
                #print(line)
                
                # Strip off the @@ characters to get only the modified line numbers. 
                clean_line = line.split('@@')[1]
                
                # Get the characters after the + sign, as these are the 
                # line numbers of added lines. 
                half_line = clean_line.split('+')[1]
                #print(half_line)
                
                # Get the number before the , as the start of the lines to blame
                start = int(half_line.split(',')[0])
                
                # If there is no ',' then only one line was changed so length = 1
                # Otherwise number after the comma is number of lines to blame
                if ',' in half_line:
                    length = int(half_line.split(',')[1])
                else:
                    length = 1
                #print(str(start) + ", " + str(length))
                
                # Adds which lines to blame to the set of lines to blame. 
                # EG: If the hunk header was:
                # @@ +15,3 -20,2 @@
                # Then the lines to blame are:
                # 15, 16 and 17 as this is the function which the lines added are in. 
                for number in range(start, start + length):
                    added_lines.add(number)
            
            # For each line in the no context diff. 
            for line in diff_no_context.splitlines():
                if not line.startswith('@@'):
                    continue
                #print(line)
                
                # Strip off the @@ in the hunk header
                clean_line = line.split('@@')[1]
                
                # Strip away the + character in the hunk header, as we
                # are not interested in added lines here
                half_line = clean_line.split('+')[0]
                
                # Remove the '-' character so the removed line numbers
                # are not interpreted as negative. 
                half_line = half_line.replace('-','')
                #print(half_line)
                
                # The number before the comma (if it exists) is the first
                # deleted line. 
                # If there is a comma, the number after the comma is the number
                # of deleted lines. 
                # If no comma, then only one line so length is 1. 
                start = int(half_line.split(',')[0])
                if ',' in half_line:
                    length = int(half_line.split(',')[1])
                else:
                    length = 1
                #print(str(start) + ", " + str(length))
                
                # Adds which lines to blame to the set of lines to blame. 
                # EG: If the hunk header was:
                # @@ +15,3 -20,2 @@
                # Then the lines to blame are:
                # 20 and 21 as they are the lines which have been removed. 
                for number in range(start, start + length):
                    removed_lines.add(number)
                
            #print(added_lines)
            #print(removed_lines)
        
            # The above for loop identified which lines need to be blamed, now to blame them
            # to determine the commit which last edited that line. 
            # This loop is for lines which were added, so uses the function context diff. 
            for line in added_lines:
                # If there is a flag, add it to the blame. 
                # -L n,n+1 gives the blame for line n in the file
                if this.flag == '':
                    blame = this.repo.git.blame("-L", str(line) + "," + str(line+1), commit, "--", file)
                else:
                    blame = this.repo.git.blame("-L", str(line) + "," + str(line+1), this.flag, commit, "--", file)
                    
                # Get the first token of the blame, which is the responsible commit. 
                blamed_commit = blame.split(" ")[0]
            
                # If the file was created in the current commit, the blame will flag the
                # current commit as a potential vulnerability causing commit. This if statement
                # stops this from being counted. 
                if commit.startswith(blamed_commit):
                    continue
                    
                # Increment count for the blamed commit. 
                if blamed_commit in blamed_commits:
                    blamed_commits[blamed_commit] += 1
                else:
                    blamed_commits[blamed_commit] = 1
               
                # Keep track that this is a blamed commit due to an added line. 
                if blamed_commit in added_blamed_commits:
                    added_blamed_commits[blamed_commit] += 1
                else:
                    added_blamed_commits[blamed_commit] = 1
            
            # Similar to the above loop, but uses for removed lines to uses the no context diff. 
            for line in removed_lines:
                if this.flag == '':
                    blame = this.repo.git.blame("-L", str(line) + "," + str(line+1), commit + "~", "--", file)
                else:
                    blame = this.repo.git.blame("-L", str(line) + "," + str(line+1), this.flag, commit + "~", "--", file)
                    
                blamed_commit = blame.split(" ")[0]
                
                # If the file was created in the current commit, the blame will flag the
                # current commit as a potential vulnerability causing commit. This if statement
                # stops this from being counted. 
                if commit.startswith(blamed_commit):
                    continue
            
                if blamed_commit in blamed_commits:
                    blamed_commits[blamed_commit] += 1
                else:
                    blamed_commits[blamed_commit] = 1
                    
                if blamed_commit in removed_blamed_commits:
                    removed_blamed_commits[blamed_commit] += 1
                else:
                    removed_blamed_commits[blamed_commit] = 1
        
        print("Blamed commits for lines which were added: ")
        print(added_blamed_commits)
        print("Blamed commits for lines which were removed: ")
        print(removed_blamed_commits)
        return blamed_commits
    
    # Static function - Don't call it on an instance of the class.
    # Takes the output from get_blamed_commits and returns the commit which the greatest
    # number of blames (ie returns key with the highest value)
    def select_vulnerability_causing_commit(blamed_commits):
        max_blame = 0
        commit = ''
        for key, value in blamed_commits.items():
            if value > max_blame:
                max_blame = value
                commit = key
            
        return commit


# In[5]:


# Iterate over all of the required flags
for item in ['', '-w', '-wM', '-wC', '-wCC', '-wCCC']:
    # Run the vulnerability_causing commit finder for rest repository with specified flag
    print("rest with: " + item)
    rest_vcc_finder = vulnerability_causing_commit_finder(local_link_rest, item)
    result = rest_vcc_finder.get_blamed_commits(rest_fixing_commit, rest_files)
    print("Total blamed commits: ")
    print(result)
    vulnerability_causing_commit = vulnerability_causing_commit_finder.select_vulnerability_causing_commit(result)
    print("Vulnerability Causing Commit: ")
    print(vulnerability_causing_commit)


# In[6]:


# Iterate over all of the required flags
for item in ['', '-w', '-wM', '-wC', '-wCC', '-wCCC']:
    # Run the vulnerability_causing commit finder for camel repository with specified flag
    print("camel with: " + item)
    camel_vcc_finder = vulnerability_causing_commit_finder(local_link_camel, item)
    result = camel_vcc_finder.get_blamed_commits(camel_fixing_commit, camel_files)
    print("Total blamed commits: ")
    print(result)
    vulnerability_causing_commit = vulnerability_causing_commit_finder.select_vulnerability_causing_commit(result)
    print("Vulnerability Causing Commit: ")
    print(vulnerability_causing_commit)


# In[7]:


# Iterate over all of the required flags
for item in ['', '-w', '-wM', '-wC', '-wCC', '-wCCC']:
    # Run the vulnerability_causing commit finder for struts repository with specified flag
    print("struts with: " + item)
    struts_vcc_finder = vulnerability_causing_commit_finder(local_link_struts, item)
    result = struts_vcc_finder.get_blamed_commits(struts_fixing_commit, struts_files)
    print("Total blamed commits: ")
    print(result)
    vulnerability_causing_commit = vulnerability_causing_commit_finder.select_vulnerability_causing_commit(result)
    print("Vulnerability Causing Commit: ")
    print(vulnerability_causing_commit)


# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:




