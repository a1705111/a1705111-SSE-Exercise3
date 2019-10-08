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


# Clone the repositories. This is commented out to avoid trying to double clone the repositories. 

#git.Repo.clone_from(remote_link_rest, local_link_rest)
#git.Repo.clone_from(remote_link_camel, local_link_camel)
#git.Repo.clone_from(remote_link_struts, local_link_struts)


# In[4]:


# Fixing commit and important files in that commit for the rest repository.
rest_fixing_commit = '4430e7896'
# First two are files in fixing commit, other three are related files in the vulnerability causing commit.
rest_files = ['spring-data-rest-webmvc/src/main/java/org/springframework/data/rest/webmvc/json/patch/AddOperation.java',
             'spring-data-rest-webmvc/src/main/java/org/springframework/data/rest/webmvc/json/patch/PatchOperation.java',
             'spring-data-rest-webmvc/src/main/java/org/springframework/data/rest/webmvc/config/JsonPatchHandler.java',
             'spring-data-rest-webmvc/src/main/java/org/springframework/data/rest/webmvc/json/patch/Patch.java',
             'spring-data-rest-webmvc/src/main/java/org/springframework/data/rest/webmvc/json/patch/PathToSpEL.java']

# Fixing commit and important files in that commit for the camel repository.
camel_fixing_commit = '07934f59c6a1'
# First is file from fixing commit. 
camel_files = ['camel-core/src/main/java/org/apache/camel/model/dataformat/CastorDataFormat.java',
              'components/camel-castor/src/main/java/org/apache/camel/dataformat/castor/AbstractCastorDataFormat.java',
              'camel-core/src/main/java/org/apache/camel/model/dataformat/DataFormatsDefinition.java',
              'camel-core/src/main/java/org/apache/camel/model/UnmarshalDefinition.java',
              'camel-core/src/main/java/org/apache/camel/builder/DataFormatClause.java']

# Fixing commit and important files in that commit for the struts repository. 
struts_fixing_commit = '0c543aef31'
# The first is the file in the fixing commit
# The second is a random file from the commit
# The third-fifth are files from the commit in the same directory as SecurityMemberAccess
struts_files = ['xwork-core/src/main/java/com/opensymphony/xwork2/ognl/SecurityMemberAccess.java',
               'xwork-core/src/main/java/com/opensymphony/xwork2/Action.java',
               'xwork-core/src/main/java/com/opensymphony/xwork2/ognl/accessor/ObjectAccessor.java',
               'xwork-core/src/main/java/com/opensymphony/xwork2/ognl/OgnlUtil.java',
               'xwork-core/src/main/java/com/opensymphony/xwork2/ognl/ObjectProxy.java']


# In[5]:


# Simple and reusable class for analysing vulnerabilities. 
# It is NOT designed to handle unexpected input and performs no input checking. 
# If you are using this object, be careful to ensure your input is valid. 
# By extension that also means this code is likely to be vulnerable to injection attacks.
# 
# Has no handling for cases where a multiline comment is ended on the same line as 
# a line of code - it will consider the entire line to be commented out.
# eg:
# /* start multiline comment
# */ int i = 0
# If both of those lines were deleted, without comments one line has been deleted. 
# However this class will treat that as two deleted lines. I haven't fixed this
# because anyone who puts code after the end of a multi-line commend is evil.
class vulnerability_analyser:
    # Initialises the object with the specified local_link as the github repository
    # to use. 
    def __init__(this, local_link):
        this.repo = git.Repo(local_link)
    
    # Prints out the title and the message of the commit. 
    # Also prints out if the message contains the words "bug". "vulnerability",
    # "fix" or "CVE"
    # It is recommended to check the message manually to ensure the automated answer
    # is correct. 
    def print_title(this, commit):
        # Get info on the commit with git show. 
        text = this.repo.git.show("-s", commit).splitlines()
        message = ""
        title = ""
        first = True
        
        # For each line
        for line in text:
            # Ignore lines which are not the title or message
            if line.startswith('commit'):
                continue
            if line.startswith('Author:'):
                continue
            if line.startswith('Date:'):
                continue
            if line.isspace():
                continue
            if line == "":
                continue
        
            # If first, this line is the title so print it. 
            # if not first, this line is the message so print it. 
            if first:
                print("Title: ")
                title = line
                print(line)
                first = False
            else:
                print("Message: ")
                message = line
                print(line)
        
        # Make message lowercase
        message.lower()
        # If fix, bug, vulnerability of CVE is mentioned the message probably mentions fixing
        # a bug. 
        if 'fix' in message or 'bug' in message or 'vulnerability' in message or 'CVE' in message:
            print("Message does mention fixing a bug")
        else:
            print("Message does not mention fixing a bug")
    
    # Prints the number of files changed in the specified commit. 
    def print_number_of_files_changed(this, commit):
        # Get number of files changed with git show --stat
        changed = this.repo.git.show("--stat", commit)
        # Extract the first word of the last line from the git stat.
        # This is the number of files changed. 
        print("Number of files changed: " + changed.splitlines()[-1].split()[0])
    
    # Prints the number of directories changed in the specified commit. 
    def print_number_of_directories_changed(this, commit):
        # Get the list of changed folders with git show --dirstat=files
        changed = this.repo.git.show("--dirstat=files", commit)

        changed_files = []
        # Git show displays the files changed at the end of the output,
        # One per line with a empty line between the files changed and the
        # rest of its output. 
        # So reverse the list so that the files changed are at the front of the
        # list, and stop when reaching a blank line. This gathers all the changed
        # directories. 
        for line in reversed(changed.splitlines()):
            if line.isspace() or line == "":
                break
            changed_files.append(line.split()[-1])
    
        # Count the number of non-duplicate directories changed.
        file_set = set()
        directory_count = 0
        for file in changed_files:
            if file not in file_set:
                file_set.add(file)
                directory_count += 1
    
        # print the count
        print("Number of directories changed: " + str(directory_count))
    
    # Prints the number of deleted lines, including and not including comments and whitespace. 
    def print_deleted_lines(this, commit):
        # Get the diff from git diff. commit~ is the previous commit,
        diff = this.repo.git.diff(commit + "~", commit)
        
        deleted_lines = []
        # For each line in the diff
        for line in diff.splitlines():
            # Skip blank lines
            if line == "":
                continue
            # If the line starts with a -
            if line[0] == "-":
                # If the length is 1, add to list of deleted lines.
                if len(line) == 1:
                    deleted_lines.append(line[1:].strip())
                elif line[1] != "-":
                    # If the line starts with -- it indicates the start
                    # of the diff on a new file, not a deleted line so skip it. 
                    deleted_lines.append(line[1:].strip())

        # Get the count of deleted lines. 
        deleted_line_count = len(deleted_lines)

        deleted_lines_no_comments = []
        comment = False
        
        
        # For each deleted line.
        for line in deleted_lines:
            # If line is within a multi-line comment.
            if comment:
                # If the comment ends in this line,
                # we are no longer in a comment so we can start
                # counting non-commented lines again. 
                if "*/" in line:
                    comment = False
                continue
        
            # skip completely blank lines.
            if line.isspace():
                continue
            if line == "":
                continue
            # If this line is a comment, we won't count it.
            if line[0:2] == "//": 
                continue
            # If the line starts a multiline comment and doesn't end the multi-line
            # comment in the same line, we are in a multi-line comment so stop counting lines. 
            if line[0:2] == "/*":
                if "*/" in line:
                    continue
                else:
                    comment = True
                    continue
    
            # If the line starts a multiline comment after some code,
            # and doesn't end that multiline comment, after this line
            # we are in a comment so stop counting lines. 
            if "/*" in line:
                if "*/" not in line:
                    comment = True
        
            deleted_lines_no_comments.append(line)
    
        # Get the count of deleted lines not including comments. 
        deleted_lines_count_no_comments = len(deleted_lines_no_comments)

        # print the number of deleted lines. 
        print("Number of lines deleted: " + str(deleted_line_count))
        print("Number of lines deleted (No Comments or blank lines): " + str(deleted_lines_count_no_comments))
        
    # Prints the number of added lines, including and not including comments and whitespace. 
    def print_added_lines(this, commit):
        # Get the diff from git diff. commit~ is the previous commit,
        diff = this.repo.git.diff(commit + "~", commit)
        
        added_lines = []
        # For each line in the diff
        for line in diff.splitlines():
            # Skip blank lines
            if line == "":
                continue
            # If the line starts with a +
            if line[0] == "+":
                # If the length is 1, add to list of deleted lines.
                if len(line) == 1:
                    added_lines.append(line[1:].strip())
                elif line[1] != "+":
                    # If the line starts with ++ it indicates the start
                    # of the diff on a new file, not a deleted line so skip it. 
                    added_lines.append(line[1:].strip())

        # Get the count of added lines. 
        added_line_count = len(added_lines)

        added_lines_no_comments = []
        comment = False
        
        # For each added line.
        for line in added_lines:
            # If line is within a multi-line comment.
            if comment:
                # If the comment ends in this line,
                # we are no longer in a comment so we can start
                # counting non-commented lines again. 
                if "*/" in line:
                    comment = False
                continue
        
            # skip completely blank lines.
            if line.isspace():
                continue
            if line == "":
                continue
            # If this line is a comment, we won't count it.
            if line[0:2] == "//": 
                continue
            # If the line starts a multiline comment and doesn't end the multi-line
            # comment in the same line, we are in a multi-line comment so stop counting lines. 
            if line[0:2] == "/*":
                if "*/" in line:
                    continue
                else:
                    comment = True
                    continue
    
            # If the line starts a multiline comment after some code,
            # and doesn't end that multiline comment, after this line
            # we are in a comment so stop counting lines. 
            if "/*" in line:
                if "*/" not in line:
                    comment = True
        
            added_lines_no_comments.append(line)
    
        # Get the count of deleted lines not including comments. 
        added_lines_count_no_comments = len(added_lines_no_comments)

        # print the number of deleted lines. 
        print("Number of lines added: " + str(added_line_count))
        print("Number of lines added (No Comments or blank lines): " + str(added_lines_count_no_comments))
    
    # For each file in files, prints how many days since the last commit,
    # and the number of times that file has been modified. 
    def get_last_commits_to_files(this, commit, files):
        # For each file
        for file in files:
            # Initially, the number of days since last edit is the max timedelta. 
            days_since_last_edit = datetime.timedelta.max
            
            # Get the dates with git log --pretty=%ci --follow commit -- file.
            # --pretty=%ci means only the date is included. 
            dates = this.repo.git.log("--pretty=%ci", "--follow", commit, "--", file).splitlines()
            
            # The total number of modifications to this file is the length of the log. 
            modification_count = len(dates)
            
            commit_date = datetime.datetime.strptime(this.repo.git.show("-s", "--pretty=%ai", commit), "%Y-%m-%d %H:%M:%S %z")
            
            # Find the most recent modification to this file. 
            for date in dates:
                date_obj = datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S %z")
                
                # Ignore any commits which are after the current commit. 
                # Due to the distributed nature of git, commits are not neccesarily in chronological
                # order so a commit made to the file after the commit in question could end up before it
                # in the hierarchy.
                # So ignore files with dates after the commit in question. 
                if commit_date > date_obj:
                    date_diff = commit_date - date_obj
                    # If this commit is more recent than the most recent
                    # commit we have found, set it to be the last commit to this file. 
                    if date_diff < days_since_last_edit:
                        days_since_last_edit = date_diff
                        
            if days_since_last_edit == datetime.timedelta.max:
                # If the days since last edit is timedelta max, then there was no previous commit to
                # the file.
                print("There was no previous commit to file: " + file)
            else:
                # Print how long ago the last commit to the file was. 
                print("Previous commit to file: " + file + " was " + str(days_since_last_edit.days) + " days before")
            
            # Print out the modification count.
            print("And has been modified: " + str(modification_count) + " times")
            print("--")
    
    # Prints the authors which have modified each file
    # and prints the total count of commits made by each of these authors. 
    # Classifies authors as experienced if they have made more than 200 commits. 
    def get_authors(this, commit, files):
        # Keep track of all the authors with this set. 
        all_authors = set()
        for file in files:
            # Keep track of the authors for this file with a set.
            authors = set()
            # --pretty=%an causes git log to only return the author's name. 
            log = this.repo.git.log("--pretty=%an", "--follow",commit,  "--", file ).splitlines()
            # For each line
            for line in log:
                # Add to the sets. Adding a duplicate to a set does nothing,
                # so no need to check. 
                authors.add(line)
                all_authors.add(line)
            # Print out the file and the authors which have edited it. 
            print("The authors which have edited: " + file + ":")
            for author in authors:
                print(author)
            print("--")
        
        # Get a list of all authors along with number of commits. 
        commit_authors = this.repo.git.shortlog("-sn", "--all").splitlines()
        author_commits = []

        # For each author
        for commit_author in commit_authors:
            commit, author = commit_author.split("\t")
            # If they have modified one of the files,
            # add them to the list of authors to display.
            if author in all_authors:
                author_commits.append([commit.strip(), author])
    
        # Print out the number of commits each author has made,
        # and classify them as experienced if they have made
        # more than 200 commits. 
        for author in author_commits:
            print(author[1] + " has made: " + author[0] + " commits")
            if int(author[0]) > 200:
                print(author[1] + " is an experienced author")
    
    # Runs all of the above functions on the specified commit and with the specified set of
    # files. 
    def print_summary(this, commit, files):
        this.print_title(commit)
        this.print_number_of_files_changed(commit)
        this.print_number_of_directories_changed(commit)
        this.print_deleted_lines(commit)
        this.print_added_lines(commit)
        this.get_last_commits_to_files(commit, files)
        this.get_authors(commit, files)


# In[6]:


# Run the analyser on the spring repository.
spring_analyser = vulnerability_analyser(local_link_rest)
spring_analyser.print_summary(rest_fixing_commit, rest_files)


# In[7]:


# Run the analyser on the camel repository.
camel_analyser = vulnerability_analyser(local_link_camel)
camel_analyser.print_summary(camel_fixing_commit, camel_files)


# In[8]:


# Run the analyser on the struts repository.
struts_analyser = vulnerability_analyser(local_link_struts)
struts_analyser.print_summary(struts_fixing_commit, struts_files)

