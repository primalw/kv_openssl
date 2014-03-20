#!/usr/bin/env python

import glob
import os
import sys
import fnmatch
import re
from collections import deque

''' Map of successfully found functions '''
funcMap = set()
''' Map of unsuccessfully found functions '''
ntFoundFunc = set()
''' Queue of traced function headers '''
fDeclaration = deque()
''' Queue of traced function definitions '''
fDefinition = deque()
''' Queue of used global variables '''
gVariable = deque()
''' Queue of customly defined data types '''
cDefinition = deque()
''' Queue of traced data definitions '''
dDefinition = deque()
''' Queue of found data definitions '''
dFound = deque()

reserveWords = [ "auto", "if", "break", "int", "case", "long", "char", "register", "continue", "return", "default", "short", "do", "sizeof", "double", "static", \
                        "else", "struct", "entry", "switch", "extern", "typedef", "float", "union", "for", "unsigned", "goto", "while", "enum", "void", "const", "signed", \
                         "volatile", "null", "stderr", "fprintf", "memset", "malloc", "true", "false", "define", "elif"]

def stripped(x):
    ''' Removes all control characters from a string '''
    return "".join([i for i in str(x) if ord(i) in range(32, 127)])

def clean(x):
    inter = tsplit(x,('\\s', '\\t', '\\n', '\\r'))

    for y in inter:
        if (y.strip()):
            return y.strip()
    
def tsplit(string, delimiters):
    """Behaves str.split but supports multiple delimiters."""
    
    delimiters = tuple(delimiters)
    stack = [string,]
    
    for delimiter in delimiters:
        for i, substring in enumerate(stack):
            substack = str(substring).split(delimiter)
            stack.pop(i)
            for j, _substring in enumerate(substack):
                stack.insert(i+j, _substring)
            
    return stack

def  cleanFunctionName(name):
    ''' Splits using all the non word characters '''
    clnList = tsplit(name,('\\s', '*', '=', ',','~','!','@','#','$','%','^','&','*','+','=','`','[',']','\\','{','}','|',';',':','<','>','/','?','.',')','\\t',' ','-'))
    return clnList[ len(clnList) -1 ].strip()

def clearComments(line, higherComment):
    ''' Clear comment segments from a line / string and returns a list of cleared segments '''
    cleanLine = line
    cleanSet = []
    final = []

    if (not higherComment and not ( cleanLine.count("/*") or cleanLine.count("*/") ) ):
        return cleanSet

    if ( higherComment and ( re.findall("^.*\*/\s*$", line ) ) and not line.count("/*") ):
        return cleanSet

    if ( re.findall("^\s*/\*.*$", line) and not line.count("*/")):
        return cleanSet
        
    if cleanLine.count("//") == 1:
        cleanLine = cleanLine.split("//",2)[0]
        cleanSet.append(cleanLine)

    if cleanLine.count("/*") > 0:
        cleanLine = cleanLine.split("/*")

        for seg in cleanLine:
            seg = seg.strip()
            if ( seg and seg.count("*/") ):
                cleanSet.append(seg.split("*/",2)[1])
            elif ( seg and not seg.count("*/") ):
                cleanSet.append(seg)
    else:
        cleanSet.append(cleanLine)

    for cleaned in cleanSet:
        qts = re.findall("(.*)\".*?[\n]?\"(.*)", cleaned)
        
        if ( not qts ):
            final.append(cleaned)
            continue

        cleaned = re.findall("\s*\((.*)\)\s*",  str(qts[0]) )[0].split(",")
        for clean in cleaned:
            if ( clean.strip() ):
                clean = re.findall("^\s*'?(.*[^'])'?\s*$", clean.strip())
                final.append(clean)

    return final

def extractVariables(code, fList, cond ):
    ''' Looking for variables and custom types being used '''

    ''' All the variables used in the  function body '''
    tempVariables = deque()
    ''' Locally defined variables'''
    tempLVariables = deque()
    ''' All the types of variables used '''
    tempTypes = deque()

 #   print "================= Variable Extraction ================"
    i = 0
    cStart = 0
    cEnd = 0
    argFinding = True
    argPatterns = ["\((.*[^\)])\)", "^(.*)$", "\(?(.*)\)"]
    templates = [ "\s*\{?\s*([A-Za-z0-9_]+)([A-Za-z0-9_\*\s]*)\s+\**\s*([A-Za-z0-9_]+)\s*\[(.*)\][=;\s]", \
                          "^\s*\{?\s*([A-Za-z0-9_]+)([A-Za-z0-9_\*\s]*)\s+\**\s*([A-Za-z0-9_,]+)\s*;$", \
                          "\s*\{?\s*([A-Za-z0-9_]+)([A-Za-z0-9_\*\s]*)\s+\**\s*([A-Za-z0-9_]+)\s*=(.*[^;]);?", \
                          "\s*\{?\s*([A-Za-z0-9_]+)([A-Za-z0-9_\*\s]*)\s+\**\s*([A-Za-z0-9_,]+)\s*;"]
                          

    for num in range( len(code) ):

        orgLine = code.popleft().strip()

        if ( re.findall("^\s*#.*$", orgLine) ):
            continue

        cStart += orgLine.count('/*');
        cEnd += orgLine.count('*/');

        if ( cStart != cEnd ):
            continue

        ''' Extracting argument list '''
        if ( argFinding and cond):
            
            if ( ")" in orgLine):
                 argFinding = False
                 if ( num == 0 ):
                     regex = argPatterns[0]
                 else:
                     regex = argPatterns[2]
            else:
                 if ( num == 0 ):
                     regex = argPatterns[0]
                 else:
                     regex = argPatterns[1]
                 
                 
            arglist = re.findall(regex, orgLine)
            if ( arglist ):
                arglist = arglist[0].split(",")
   
            for arg in arglist:
                argListItems = arg.strip().split()

                i = 0
                for item in argListItems:
                    if ( len(item) > 0):
                        if ( not i == len(argListItems)-1 ):
                            if ( not item in tempTypes):
                                tempTypes.append(item)
                        else:
                            if ( not re.findall("^\s*\**\s*(.*)", item)[0] in tempLVariables ):
                                tempLVariables.append(re.findall("^\s*\**\s*(.*)", item)[0])
                    i += 1
        else:
##            ''' case: type var[]; '''
##            seg = re.findall("^\s*\{?\s*([A-Za-z0-9_]+)([A-Za-z0-9_\*\s]*)\s+\**\s*([A-Za-z0-9_]+)\s*\[(.*)\].*$", orgLine)
##            if ( not seg ):                
##                ''' case: type var; '''
##                seg = re.findall("^\s*\{?\s*([A-Za-z0-9_]+)([A-Za-z0-9_\*\s]*)\s+\**\s*([A-Za-z0-9_,]+)\s*;$", orgLine)
##                if ( not seg ):        
##                    ''' case: type var = var | value ; '''
##                    seg = re.findall("^\s*\{?\s*([A-Za-z0-9_]+)([A-Za-z0-9_\*\s]*)\s+\**\s*([A-Za-z0-9_]+)\s*=(.*[^;]);?$", orgLine)
##                    if ( not seg ):
##                        ''' case: { void *p; int f*; }; '''
##                        seg = re.findall("\s*\{?\s*([A-Za-z0-9_]+)([A-Za-z0-9_\*\s]*)\s+\**\s*([A-Za-z0-9_,]+)\s*;", orgLine)
                    
            for template in templates:
                seg = re.findall(template, orgLine)
                for x in seg:
                    i = 0
                    segSplit = re.findall("\s*\((.*)\)\s*",str(x))[0].split(",")

                    for item in segSplit:
                        item = re.findall("^\s*'?(.*[^'])'?\s*$", item.strip())

                        if item :
                            item = clean(item[0])
                    
                        if ( item and not ( item in tempLVariables or item in fList or item in reserveWords or item in tempVariables) ):
                            if ( i == 0 ):
                                tempTypes.append(item.strip())
                            elif ( i == 1 ):
                                subTypes = item.split()

                                for subType in subTypes:
                                    subType = clean(subType)
                                    if ( subType.count("*") ):
                                        subType = re.findall("\**\s*([A-Za-z0-9_]+)\s*\**)", subType)[0]
                                        subType = clean(subType)
                                    if ( subType and not ( subType in tempLVariables or subType in fList or subType in reserveWords or subType in tempVariables) ):
                                        tempTypes.append(subType)
                                    
                            elif ( i == 2 ):
                                tempLVariables.append(item.strip())
                            else:
                                rem = item
                                ''' case: type var1 = var2; '''
                                match = re.findall("^\s*([A-Za-z0-9_]+)\s*;?\*$", rem)
                                if ( match and not clean(match[0]).isdigit() and not clean(match[0]) in tempVariables and not clann(match[0]) in fList):
                                    tempVariables.append(clean(match[0]))

                                ''' case: type var1 = (*type)var2; '''
                                match = re.findall("\S*\s*\(\s*\**\s*([A-Za-z0-9_]+\s*)\)[A-Za-z0-9_]+", rem)
                                for typeM in match:
                                    typeM = clean(typeM)
                                    if ( typeM and not typeM.isdigit()and not typeM in tempTypes and not typeM in fList):
                                        tempTypes.append(typeM)
                                                                                                   
                        i += 1

            ''' case: (*type) var op (type) var'''
            seg = re.findall("\S*\s*\(\s*\**\s*([A-Za-z0-9_]+\s*)\)[A-Za-z0-9_]+", orgLine)
            for typeM in seg:
                typeM = clean(typeM)
                if ( typeM and not typeM.isdigit() and not typeM in fList):
                    tempTypes.append(typeM)

            ''' General splitting to extract the generic most case '''
            regex = re.compile(r'[\n\r\t]')
            orgLine = regex.sub(' ', str(orgLine))
            cleaned = clearComments(orgLine.strip(), True)
            for seg in cleaned:
                seg = tsplit(seg,('\s', '*', '=', ',','~','!','@','#','$','%','^','&','*','+','=','`','[',']','{','}','|',';',':','<','>','/','?','.','(',')','\t', ' ','-', '\r','\\'))
                for typeM in seg:
                    if ( typeM.strip() and not ( len(typeM.strip()) == 1 and typeM.count("'") == 1) ):
                        typeM = clean(re.findall("^\s*'?(.*[^'])'?\s*$", typeM)[0])
                        if ( typeM and not typeM.isdigit() and not ( typeM in tempTypes or typeM in tempLVariables or typeM in fList or typeM in tempVariables ) ):
                            tempVariables.append(typeM)
                
    for ctype in tempTypes:
        ctype = clean(ctype)
        if ( not ( ctype.lower() in reserveWords or ctype in cDefinition or ctype in fList or ctype in gVariable or ctype in dFound )):
            print "Type : "+ctype           
            cDefinition.append(ctype)

    for var in tempVariables:
        var = clean(var)
        if ( not ( var in tempLVariables or var in gVariable or var.lower() in reserveWords or var in fList or var in cDefinition or var in dFound )):
            print "Var : "+var.strip()
            gVariable.append(var.strip())

def varSearch(rootPath):
    ''' Recursively search for global variables and custom data types '''
    patterns = ["*.h","*.c*"] 

    for pattern in patterns:
        for root, dirnames, filenames in os.walk(rootPath):
            for filename in fnmatch.filter(filenames, pattern):            
                with open(os.path.join(root, filename), 'r') as inF:
                    inStruct = False
                    structData = deque()
                    inMacro = 0
                    preProcessorQ = deque()
                    tempCode = deque()
                    found = False
                    cStart = 0
                    cEnd = 0
                    sCount = 0
                    eCount = 0
                    mcrCount = 0
                    lineNum = 0

                    for line in inF:

                        orgLine = line
                        lineNum += 1

                        if ( not line.strip() ):
                            continue
                    
                        cStart += orgLine.count('/*');
                        cEnd += orgLine.count('*/');

                        if ( cStart != cEnd ):
                            if ( orgLine.count('/*') or orgLine.count('*/') ):
                                #print orgLine
                                orgLine = clearComments(orgLine, False)
                                if ( not len(orgLine) ):
                                    continue
                                else:
                                    orgLine = orgLine[0]
                            else:
                                continue
                        
                        sCount += orgLine.count('{');
                        eCount += orgLine.count('}');


                        if ( orgLine and not ( re.findall("^\s*\w*\s*struct.*$", orgLine) ) ):
                            if ( ( sCount != eCount) or ( not orgLine.count("{" ) and re.findall("^.*\}\s*$", orgLine) ) ):
                                continue

                        ''' Keeping track of preprocessor directives '''    
                        if ( re.findall('^\s*#\s*if.*$', orgLine ) ):
                            preProcessorQ.append(orgLine)
                            mcrCount += 1
                            continue
                        else :
                            ''' To remove unwanted preprocessor directives '''
                            if ( re.findall('^\s*#\s*endif.*$', orgLine) ):
                                mcrCount -= 1
                                temp = ""

                                skip = False
                                #print "/* file: "+str(root) +"/" +str(filename)+" :"+str(lineNum)+" */\n"
                                #print preProcessorQ
                                temp = preProcessorQ.pop()
                                if ( re.findall('^\s*#\s*if.*$', temp ) ):
                                    skip = True

                                elif ( re.findall('^\s*#\s*else.*$', temp) ):
                                    temp = preProcessorQ.pop()                 
                                    if ( re.findall('^\s*#\s*if.*$', temp) ):
                                        skip = True

                                elif ( re.findall('^\s*#\s*elif.*$', temp) ):
                                    skip = True

                                if ( not skip ):                                    
                                    preProcessorQ.append(temp)
                                    preProcessorQ.append(orgLine)

                                if ( not mcrCount ):
                                    if ( found ):
                                        for i in range( len(preProcessorQ) ):
                                            dDefinition.append(preProcessorQ.popleft())
                                        found = False
                                    preProcessorQ.clear()
                                continue

                            elif ( re.findall('^\s*#\s*else.*$', orgLine) ):
                                temp = preProcessorQ.pop()                 
                                if ( re.findall('^\s*#\s*elif.*$', temp) ):
                                    continue
                                else:
                                    preProcessorQ.append(temp)
                                    preProcessorQ.append(orgLine)
                                    
                            elif ( re.findall('^\s*#\s*elif.*', orgLine) ):
                                preProcessorQ.append(orgLine)
                                continue
                            
                            elif ( re.findall('^\s*#\s*include.*', orgLine) ):
                                if ( mcrCount ):
                                    preProcessorQ.append(orgLine)
                                else:
                                    dDefinition.append(orgLine)
                                continue
                            
                            elif ( re.findall('^\s*#\s*define.*$', orgLine) ):
                                if ( mcrCount ):
                                    preProcessorQ.append(orgLine)
                                else:
                                    dDefinition.append(orgLine)
                                continue

                            elif ( re.findall('^\s*#\s*error.*$', orgLine) ):
                                if ( mcrCount ):
                                    preProcessorQ.append(orgLine)
                                else:
                                    dDefinition.append(orgLine)
                                continue

                        if ( re.findall("^\s*#\s*define\s+([A-Za-z0-9_]*)\s+[A-Za-z0-9_]+\s*.*$", orgLine) ):
                            name = re.findall("^\s*#\s*define\s*([A-Za-z0-9_]*)\s+[A-Za-z0-9_]+\s*.*$", orgLine)[0].strip()
                            if ( name in gVariable or name in cDefinition ):
                                tempCode.append(orgLine)

                                while ( not stripped(orgLine).endswith("\\") ):
                                    orgLine = inF.next()
                                    tempCode.append(orgLine)

                                    if ( mcrCount ):
                                        preProcessorQ.append(orgLine)
                                    else:
                                        dDefinition.append(orgLine)

                                extractVariables(tempCode, [], False)

                                print "Found :"+name

                                if ( name in gVariable ):
                                    gVariable.remove(name)
                                elif ( name in cDefinition ):
                                    cDefinition.remove(name)
                                dFound.append(name)
                                continue
                            else:
                                while ( re.findall("^.*\s*.*\\\s*$", orgLine ) ):
                                        orgLine = inF.next()
                                               
                        elif ( re.findall("^\s*[A-Za-z0-9_]+[A-Za-z0-9_\*\s]*\s+\**\s*([A-Za-z0-9_]+)\s*;?\{?$", orgLine) ):
                            seg = re.findall("^\s*[A-Za-z0-9_]+[A-Za-z0-9_\*\s]*\s+\**\s*([A-Za-z0-9_]+)\s*;?\{?$", orgLine)                                 
                        elif ( re.findall("^\s*[A-Za-z0-9_]+[A-Za-z0-9_\*\s]*\s+\**\s*([A-Za-z0-9_]+)\s*=.*$", orgLine) ):
                            seg = re.findall("^\s*[A-Za-z0-9_]+[A-Za-z0-9_\*\s]*\s+\**\s*([A-Za-z0-9_]+)\s*=.*$", orgLine)                        
                        elif ( re.findall("^\s*[A-Za-z0-9_]+[A-Za-z0-9_\*\s]*\s+\**\s*([A-Za-z0-9_]+)\s*\[.*\].*$", orgLine) ):
                            seg = re.findall("^\s*[A-Za-z0-9_]+[A-Za-z0-9_\*\s]*\s+\**\s*([A-Za-z0-9_]+)\s*\[.*\].*$", orgLine)
                        else:
                            continue

                        name = seg[0].strip()
                        #print "Found :"+name
                        if ( name in gVariable or name in cDefinition ):
                            funcDefn = False
                            funcFound = True
                            func = False
                            qTemp = deque()
                            start = 0
                            end = 0
                            line = orgLine
                            funcName =  ""
                            funcPattern = [ "^.*\(.*\*\s*(\S+)\)\s*\(.*", "^\s*[^\W]\S+.*[^\W]\s+\*?(\S+)\s*\(.*"]

                            if ( mcrCount ):
                                preProcessorQ.append("/* file: "+str(root) +"/"+ str(filename)+" */\n")
                                for i in range( len(structData) ):
                                    preProcessorQ.append(structData.popleft())
                                preProcessorQ.append("\n")
                                found = True
                            else :
                                dDefinition.append("/* file : "+str(root) +"/"+ str(filename)+" */\n")
                                for i in range( len(structData) ):
                                    dDefinition.append(structData.popleft())
                                dDefinition.append("\n")
                                found = False
                            
                            while True:                                             
                                if ( "{" in line and not funcDefn ):
                                    funcDefn = True

                                for pattern in funcPattern:
                                    funcName = re.findall(pattern, line)
                                    if ( funcName ):
                                        func = True
                                        if ( funcName in funcmap or funcName in ntFoundFunc ):
                                            funcFound = False
                                            break

                                if ( funcFound ):    
                                    if ( mcrCount ):
                                        preProcessorQ.append(line)
                                    else:
                                        dDefinition.append(line)
                                elif ( not func ):
                                    qTemp.append(line)

                                if ( funcDefn ):
                                    start += line.count('{')
                                    end += line.count('}')

                                    if ( start == end ):
                                        break
                                else:
                                    if ( re.findall("^.*;\s*", line) ):
                                        break
                                line = inF.next()

                            extractVariables(qTemp, [], False)

                            if ( name in gVariable ):
                                gVariable.remove(name)
                            elif ( name in cDefinition ):
                                cDefinition.remove(name)
                            dFound.append(name)
                            

                        if ( not ( len(gVariable) or len(cDefinition) ) ):
                             break
                    if ( not ( len(gVariable) or len(cDefinition) ) ):
                        break
                if ( not ( len(gVariable) or len(cDefinition) ) ):
                    break
            if ( not ( len(gVariable) or len(cDefinition) ) ):
                break
        if ( not ( len(gVariable) or len(cDefinition) ) ):
            break

                            
def recFuncSearch(rootPath, funcName, rootFile):
    ''' Recursively searches for a given function name '''

    found = False
    macro = False
    clnSegments = []
    fList = []
    fnrSegments = []
    temp = []
    lineNum = 0
    inDef = False
    mcrCount = 0
    fList = []
    patterns = ["*.h","*.c*"]
    done = False
    funcDefn = False
    localFile = ""    

    ''' To avoid repeating previously searched functions
       polymorphism is not supported.'''
    if  ( ( funcName in ntFoundFunc) or ( funcName in funcMap ) ):
        return
    
    print "Looking for "+funcName
    
    ''' Recursively searches for the given function header '''
    for pattern in patterns:
        for root, dirnames, filenames in os.walk(rootPath):
            for filename in fnmatch.filter(filenames, pattern):            
                with open(os.path.join(root, filename), 'r') as inF:
                    
                    lineNum = 0
                    cStart = 0
                    cEnd = 0
                    sCount = 0
                    eCount = 0
                    inMacro = False
                    orgLine = ""
                    mcrCount = 0
                    preProcessorQ = deque()
                    preProcessorQIgn = 0
                    found = False
                    macro = False
                    clnSegments = []
                    fList = []
                    fnrSegments = []
                    temp = []
                    inDef = False
                    insSturct = 0
                    
                    for line in inF:   
                        orgLine = line
                        line = stripped(line)
                        fnrSegments = []
                        lineNum += 1

                        '''Following counts are needed to make sure that we dont
                        look for declaration within comments and other definitions '''    
                        cStart += orgLine.count('/*');
                        cEnd += orgLine.count('*/');

                        if ( cStart != cEnd ):
                            continue
                        
                        sCount += orgLine.count('{');
                        eCount += orgLine.count('}');

                        if len( re.findall("^.*extern.*\{.*$", line) ):
                            sCount -= sCount

                        if ( ( sCount != eCount) and not re.findall("^.*\{.*$", orgLine ) ) or re.findall("^\s*//.*$", orgLine  ):
                            continue
                            
                        if funcName in line and not inMacro and (not re.findall('^#\s*if.*', line) ) :

                            ''' Looking for function pointer template match '''
                            match = re.findall('^.*\(.*\*\s*(\S+)\)\s*\(.*', orgLine)
                            if ( match and match[0] == funcName ):
                                fDeclaration.append("/* file: "+funcName+" : "+str(root) + str(filename)+" */\n")

                                ''' Flushing preprocessor '''
                                for i in range( len(preProcessorQ) ):
                                    fDeclaration.append(preProcessorQ.popleft())
                                    
                                print orgLine,
                                fDeclaration.append(orgLine)

                                while ( not stripped(line).endswith(";") ):  
                                    line = inF.next()
                                    print line,
                                    fDeclaration.append(line)

                                ''' Recursively searches for a given function name '''
                                if ( "=" in line ):
                                    subsName = line.split("=",2)[1].split(";")[0]
                                    if ( ( subsName.lower() != "null" ) and ( subsName != "0" ) ):
                                        fList.append(subsName)

                                found = True
                                done = True
                                funcMap.add(funcName)
                                
                                if ( mcrCount ):
                                    continue
                                else:
                                    break

                            ''' Look for Macros and Generic function header templates '''
                            if ( line.startswith("#") ):
                                regex = '^\s*#\s*define\s(\S+)\s*\(.*'
                            else:
                                regex = '^\s*[^\W]\S+.*[^\W]\s+\*?(\S+)\s*\(.*'
                                
                            match = re.findall(regex, orgLine)
                            if ( match and ( match[0] == funcName or ( match[0].count("(") and ( match[0].split("(",2)[0] == funcName ) ) ) ):

                                    found = True
                                    fHdr = orgLine
                                    funcMap.add(funcName)

                                    ''' if the function is a macro '''
                                    if ( re.findall("^\s*#\s*.*$", orgLine) ):

                                        fDeclaration.append("/* file: "+funcName+" : "+str(root) + str(filename)+" */\n") 
                                        for i in range( len(preProcessorQ) ):
                                            fDeclaration.append(preProcessorQ.popleft())
                                               
                                        fDeclaration.append(orgLine)
                                        print orgLine,

                                        ''' Looking for other function calls within the macro '''
                                        while True:
                                            if ( line.count('(') and (not fHdr.startswith("//") ) and ( cStart == cEnd )):
                                                clnSegments = clearComments(line, ( cStart == cEnd ))
                                                for seg in clnSegments:
                                                    paraList = seg.split("(");
                                                    for slc in paraList:
                                                        slc = slc.split()[ len( slc.split() ) - 1 ]
                                                        slc = cleanFunctionName(slc)
                                                        slc = clean(slc)
                                                        if ( slc and slc != funcName and i < seg.count("(") ):
                                                            if(  len (re.findall("[^=\+\?\.\*\^\$\(\)\[\]\{\}\|\\!@#%&\"\'/\s\-<>:;`]", slc.strip())) == len(slc.strip())):
                                                                fList.append(slc)
                                                        i += 1

                                            if (not line.endswith("\\") ):
                                                break
                                                
                                            line = inF.next()
                                            orgLine = line
                                            line = stripped(line)
                                            cStart += line.count('/*')
                                            cEnd += line.count('*/')
                                            print orgLine,
                                            fDeclaration.append(orgLine)
                                    else:
                                        funcDefn = False
                                        qTemp = deque()
                                        tempCode = deque() 
                                        start = 0
                                        end = 0
                                        line = orgLine
                                        
                                        while True:                                             
                                            if ( "{" in line and not funcDefn ):
                                                funcDefn = True
                                                
                                            qTemp.append(line)
                                            tempCode.append(line)

                                            if ( funcDefn ):
                                                start += line.count('{')
                                                end += line.count('}')

                                                if ( start == end ):
                                                    break
                                            else:
                                                if ( re.findall("^.*;\s*", line) ):
                                                    break
                                            line = inF.next()

                                        if ( not funcDefn ):
                                            fDeclaration.append("/* file: "+funcName+" : "+str(root) + str(filename)+" */\n") 
                                            for i in range( len(preProcessorQ) ):
                                                fDeclaration.append(preProcessorQ.popleft())
                                        
                                            for i in range( len(qTemp) ):
                                                fDeclaration.append(qTemp.popleft())                                                
                                                
                                        if ( funcDefn ):
                                            done = True
                                            fDeclaration.append("/* file: "+funcName+" : "+str(root) + str(filename)+" */\n")
                                            for i in range( len(preProcessorQ) ):
                                                fDeclaration.append(preProcessorQ.popleft())
                                                
                                            for i in range( len(qTemp) ):
                                                ln = qTemp.popleft()
                                                i = 0
                                                if ( ln.count('(') and sCount > 0 and ( cStart == cEnd ) and (not ln.startswith("//") ) and ( not ln.startswith("#") ) ):
                                                    regex = re.compile(r'[\n\r\t]')
                                                    ln = regex.sub(' ', str(ln))
                                                    cleaned = clearComments(ln, True)
                                                    print cleaned
                                                    for cln in cleaned:
                                                        for x in str(cln).split("("):
                                                            paraList.append(x)

                                                    for slc in paraList:
                                                        if ( slc.strip() ):
                                                            slc = slc.split()[ len( slc.split() ) - 1 ]
                                                            slc = cleanFunctionName(slc)
                                                            slc = clean(slc)
                                                            if ( slc and slc != funcName and i < ln.count("(") ):
                                                                if(  len (re.findall("[^=\+\?\.\*\^\$\(\)\[\]\{\}\|\\!@#%&\"\'/\s\-<>:;`]", slc.strip())) == len(slc.strip())):
                                                                    fList.append(slc)
                                                        i += 1
                                                                 
                                                print ln,
                                                fDeclaration.append(ln)
                                                
                                                cStart += ln.count('/*');
                                                cEnd += ln.count('*/');

                                            extractVariables(tempCode, fList, True)
                                                
                        else:
                            if ( not inMacro and orgLine.startswith("#") and  line.endswith("\\") ):
                                inMacro = True
                            elif ( inMacro and not line.endswith("\\")):
                                inMacro = False

                            ''' Keeping track of preprocessor directives '''    
                            match = re.findall('^#\s*if.*', line )
                            if ( match ):
                                if ( found ):
                                    preProcessorQIgn += 1
                                else :
                                    preProcessorQ.append(orgLine)
                                    inDef = True;
                                    mcrCount += 1
                            else :
                                ''' To remove unwanted preprocessor directives '''
                                match = re.findall('^#\s*end.*', stripped(line))
                                if ( match ):
                                    if ( preProcessorQIgn ):
                                        preProcessorQIgn -= 1
                                    else :
                                        mcrCount -= 1
                                        inDef = False
                                        #print lineNum
                                        if ( found ):
                                            print orgLine,
                                            fDeclaration.append(orgLine)
                                            if ( not mcrCount ):
                                                break
                                            
                                        if ( len(preProcessorQ)  ):
                                            preProcessorQ.pop()
                                        
                                if ( re.findall('^#\s*else.*', orgLine) and found and not preProcessorQIgn and mcrCount):
                                    print orgLine,
                                    fDeclaration.append(orgLine)

                                if ( re.findall('^#\s*elif.*', orgLine) and found ):
                                    print orgLine,
                                    preProcessorQ.append(orgLine)

                        ''' If the function header is within preprocessor directive keep on looking for alternative delarations'''
                        if ( found and not mcrCount ) :
                            break
                    if ( found ) :
                        break
                if ( found ) :
                    break
            if ( found ) :
                break
            
        print pattern
        if ( found ) :
            break
    
    fListCln = []
    
    ''' Cleaning potential function calls '''
    for fListItem in fList:
        funcNameCln = cleanFunctionName(fListItem) 
        if ( ( not funcNameCln in reserveWords ) and len(funcNameCln) > 0 and not funcNameCln == funcName ):  
            if not ( ( funcNameCln in ntFoundFunc) or ( funcNameCln in funcMap ) or ( funcNameCln in fListCln ) ):
                print "Adding Function "+funcNameCln
                fListCln.append(funcNameCln)

    ''' Begins the recursive search for confirmed function calls '''
    for funcNameCln in fListCln:
        #recFuncSearch(rootPath, funcNameCln, str(root)+"/"+filename)
        pass
            
    if ( len(fList) or done ):
        ''' Declaration is found and its either a macro or function pointer '''
        fDeclaration.append("\n")
        return
                        
    if (not found):
        ''' Function declaration is not found '''
        ntFoundFunc.add(funcName)
        rootPath = rootFile
        fHdrCln = funcName
        print funcName+" - definition is not found - "+ rootPath
        return
    else:
        ''' Generic function header is found '''
        fHdrCln = fHdr.split("(")[0]
        print fHdrCln
        found = False
        fDeclaration.append("\n")
        
    patterns = [ "^\s*"+fHdrCln+"\s*\(.*[^;]\s*$", "^\s*[^\W]\S+.*[^\W]\s+\*?("+funcName+")\s*\(.*[^;]\s*$"]
    
    ''' Search begins for function definitions '''
    for pattern in patterns:
        for root, dirnames, filenames in os.walk(rootPath):
            for filename in fnmatch.filter(filenames, '*.c*'):           
                with open(os.path.join(root, filename), 'r') as inF:
                                
                    cStart = 0
                    cEnd = 0
                    lineNum = 0
                    sCount = 0
                    eCount = 0
                    inMacro = False
                    orgLine = ""
                    mcrCount = 0
                    preProcessorQ = deque()
                    preProcessorQIgn = 0
                    fList = []
                    for line in inF:                        
                        orgLine = line
                        line = stripped(line)

                        cStart += line.count('/*');
                        cEnd += line.count('*/');

                        if ( cStart != cEnd ):
                            continue

                        sCount += line.count('{');
                        eCount += line.count('}');

                        if ( sCount != eCount ):
                            continue

                        if ( re.findall("^\s*[^#][\W].*$", orgLine) ):
                            continue

                        ''' Function definition match is easier coz lengthier header removed unwanted matches '''
                        if ( re.findall( pattern, orgLine) ) and ( cStart == cEnd ):
                            if ( orgLine.count(";") and not orgLine.count("{") ):
                                continue
                            
                            ln = orgLine
                            found = True

                            sCount = 0
                            eCount = 0                       

                            fDefinition.append("/* file: "+funcName+" : "+str(root) + str(filename)+" */\n")

                            ''' Flushing of preprocessor directives '''
                            for i in range( len(preProcessorQ) ):
                                fDefinition.append(preProcessorQ.popleft())

                            tempCode = deque()    
                            
                            while True:
                                orgLine = ln
                                tempCode.append(ln)

                                ''' Looking for possible function calls within the function body ''' 
                                i = 0
                                paraList = []
                                if ( ln.count('(') and sCount > 0 and ( cStart == cEnd ) and (not ln.startswith("//") ) and ( not ln.startswith("#") ) ):
                                    regex = re.compile(r'[\n\r\t]')
                                    ln = regex.sub(' ', str(ln))
                                    cleaned = clearComments(ln, True)
                                    for cln in cleaned:
                                        for x in str(cln).split("("):
                                            paraList.append(x)
                                    
                                    for slc in paraList:
                                        if ( slc.strip() ):
                                            slc = slc.split()[ len( slc.split() ) - 1 ]
                                            slc = cleanFunctionName(slc)
                                            slc = clean(slc)
                                            if ( slc != funcName and i < ln.count("(") ):
                                                if( slc and  len (re.findall("[^=\+\?\.\*\^\$\(\)\[\]\{\}\|\\!@#%&\"\'/\s\-<>:;`]", slc.strip())) == len(slc.strip())):
                                                    fList.append(slc)
                                        i += 1
                                 
                                print orgLine,
                                fDefinition.append(orgLine)
                                
                                sCount += ln.count('{');
                                eCount += ln.count('}');
                                cStart += ln.count('/*');
                                cEnd += ln.count('*/');

                                ''' When the count of brackets equals, it signs the end of the function body '''
                                if ( ( sCount == eCount) and (eCount != 0)):
                                    break

                                ln = inF.next()                                

                            extractVariables(tempCode, fList, True)

                            print mcrCount
                            if ( not mcrCount ):
                                break
                            
                        else:
                            if ( not inMacro and orgLine.startswith("#") and  line.endswith("\\") ):
                                inMacro = True
                            elif ( inMacro and not line.endswith("\\")):
                                inMacro = False

                            ''' Keeping track of preprocessor directives ''' 
                            if ( sCount == eCount ):
                                match = re.findall('^\s*#\s*if.*', stripped(line))
                                if ( match ): 
                                    if ( found ):
                                        preProcessorQIgn += 1
                                    else :
                                        preProcessorQ.append(orgLine)
                                        inDef = True;
                                        mcrCount += 1
                                else :
                                    ''' To remove unwanted preprocessor directives '''
                                    match = re.findall('^#\s*end.*', stripped(line))
                                    if ( match ):
                                        if ( preProcessorQIgn > 0 ):
                                            preProcessorQIgn -= 1
                                        else :
                                            mcrCount -= 1
                                            inDef = False

                                            if ( found ):
                                                print orgLine,
                                                fDefinition.append(orgLine)
                                                if ( not mcrCount ):
                                                    break
                                                
                                            if ( len(preProcessorQ)  ):
                                                preProcessorQ.pop()
                                            
                                    if ( re.findall('^#\s*else.*', orgLine) and found and (not preProcessorQIgn) and mcrCount ):
                                        print orgLine,
                                        fDefinition.append(orgLine)

                                    if ( re.findall('^#\s*elif.*', orgLine) and found ):
                                        print orgLine,
                                        preProcessorQ.append(orgLine)

                    ''' Cleaning potential function calls '''
                    fListCln = []                    
                    for fListItem in fList:   
                        funcNameCln = cleanFunctionName(fListItem) 
                        if ( ( not funcNameCln in reserveWords ) and len(funcNameCln) > 0 ):                        
                            if not ( ( funcNameCln in ntFoundFunc) or ( funcNameCln in funcMap ) or ( funcNameCln in fListCln ) ):
                                print "Adding Function "+funcNameCln
                                fListCln.append(funcNameCln)

                    ''' Begins the recursive search for confirmed function calls '''
                    for funcNameCln in fListCln:
                        #recFuncSearch(rootPath, funcNameCln, str(root)+"/"+filename)
                        pass

                    if ( found and not mcrCount ):
                        return

                if ( found ):
                    return

    if ( not found ):
        print "Function Body is not found - "+ funcName
        ntFoundFunc.add(funcName)
    else:
        fDefinition.append("\n")
                                

def main(argv) :
    
    ''' parsing cmd arguments * not functioning at the moment '''
    path = sys.argv[1]
    functionName = sys.argv[2]
    
    ''' Has to be the root path of the code base '''
    path = "/Volumes/work/Phd/ECDH/kv_openssl/"
    ''' Name of the looked function '''
    functionName = "OPENSSL_isservice"

    recFuncSearch(path, functionName,".")
   # varSearch(path)

    ''' Writing all the header declarations '''
    if ( len(fDeclaration) ):
        thefile = open(functionName+".h",'w')

        for i in range( len(dDefinition) ):
            thefile.write(dDefinition.popleft())

        thefile.write("/********** Headers **********/ \n")
        
        for i in range( len(fDeclaration) ):
            thefile.write(fDeclaration.popleft())
        thefile.close()

    ''' Writing all the function definitions '''
    if ( len(fDefinition) ):
        thefile = open(functionName+".c",'w')
        for i in range( len(fDefinition) ):
            thefile.write(fDefinition.popleft())
        thefile.close()
                                            

if __name__ == "__main__":
    main(sys.argv[1:])
