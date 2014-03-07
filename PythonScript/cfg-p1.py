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

def stripped(x):
    ''' Removes all control characters from a string '''
    return "".join([i for i in x if ord(i) in range(32, 127)])
    
def tsplit(string, delimiters):
    """Behaves str.split but supports multiple delimiters."""
    
    delimiters = tuple(delimiters)
    stack = [string,]
    
    for delimiter in delimiters:
        for i, substring in enumerate(stack):
            substack = substring.split(delimiter)
            stack.pop(i)
            for j, _substring in enumerate(substack):
                stack.insert(i+j, _substring)
            
    return stack

def  cleanFunctionName(name):
    ''' Splits using all the non word characters '''
    clnList = tsplit(name,('\\s', '*', '=', ',','~','!','@','#','$','%','^','&','*','+','=','`','[',']','\\','{','}','|',';',':','<','>','/','?','.',')','\\t',' '))
    return clnList[ len(clnList) -1 ].strip()

def clearComments(line, higherComment):
    ''' Clear comment segments from a line / string and returns a list of cleared segments '''
    cleanLine = line
    cleanSet = []

    if (not higherComment and not ( cleanLine.count("/*") or cleanLine.count("*/") ) ):
        return cleanSet
    
    if cleanLine.count("//") == 1:
        cleanLine = cleanLine.split("//",2)[0]

    if cleanLine.count("/*") > 1:
        cleanLine = cleanLine.split("/*")

        for seg in cleanLine:
            if ( seg is not "" ):
                cleanSet.append(seg.split("*/",2)[1])
    else:
        cleanSet.append(cleanLine)

    return cleanSet

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
    done = False;

    ''' To stop repeating previously searched functions
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
                    fnMacro = False
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
                    
                    for line in inF:   
                        orgLine = line
                        line = stripped(line)

                        '''Following counts are needed to make sure that we dont
                        look for declaration within comments and other definitions '''    
                        cStart += orgLine.count('/*');
                        cEnd += orgLine.count('*/');
                        sCount += orgLine.count('{');
                        eCount += orgLine.count('}');
                        
                        fnrSegments = []
                        lineNum += 1

                        if "extern \"C\"" in line:
                            sCount -= sCount
                            
                        if funcName in line and not line.startswith("//") and ( sCount == eCount ) and not inMacro and not ( line.startswith("#ifndef") or line.startswith("#ifdef") ) and ( cStart == cEnd ):

                            ''' Looking for function pointer template match '''
                            match = re.findall('^.*\(.*\*\s*(\S+)\)\s*\(.*\)', orgLine)
                            if ( match and match[0] == funcName ):
                                fDeclaration.append("/* file: "+str(root) + "/" + str(filename)+" */ \n")

                                ''' Flushing preprocessor '''
                                for i in range( len(preProcessorQ) ):
                                    fDeclaration.append(preProcessorQ.popleft())
                                    
                                print orgLine,
                                fDeclaration.append(orgLine)

                                while ( not stripped(line).endswith(";") ):  
                                    line = inF.next();
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
                                regex = '^#\s*define\s(\S+)\s*\(.*'
                            else:
                                regex = '^[^\$]\s*\S+.*[^=!\(\)><]\s+\*?(\S+)\s*\(.*'
                                
                            match = re.findall(regex, orgLine)
                            if ( match and ( match[0] == funcName or ( match[0].count("(") and ( match[0].split("(",2)[0] == funcName ) ) ) ):

                                    found = True
                                    fHdr = line
                                    funcMap.add(funcName)
                                    fDeclaration.append("/* file: "+str(root) + "/" + str(filename)+" */\n")
                                    
                                    for i in range( len(preProcessorQ) ):
                                        fDeclaration.append(preProcessorQ.popleft())
                                            
                                    fDeclaration.append(orgLine)
                                    print orgLine,

                                    ''' if the function is a macro '''
                                    if "#define" in orgLine:
                                        fnMacro = True

                                        ''' Looking for other function calls within the macro '''
                                        while True:
                                            if ( line.count('(') and (not fHdr.startswith("//") ) and ( cStart == cEnd )):
                                                clnSegments = clearComments(line, ( cStart == cEnd ))
                                                for seg in clnSegments:
                                                    i = seg.count('(')                                                    
                                                    paraList = seg.split("(");
                                                    for slc in paraList:
                                                        if ( slc and slc != funcName and i ):
                                                            if ( slc.count('\'') != 1 or slc.count('\"') != 1 or  slc.count('//') != 1 or slc.count('/*') != 1 ):
                                                                if( not slc.strip().endswith(("=","'","+","-","/","*")) ):
                                                                    fList.append(slc)
                                                        i -= 1

                                            if (not line.endswith("\\") ):
                                                break
                                                
                                            line = inF.next()
                                            orgLine = line
                                            line = stripped(line)
                                            cStart += line.count('/*');
                                            cEnd += line.count('*/');
                                            print orgLine,
                                            fDeclaration.append(orgLine)
                                    else:
                                        ''' For generic function headers '''
                                        while ( not stripped(line).endswith(";") ):  
                                            line = inF.next();
                                            print line,
                                            fDeclaration.append(line)
                                        
                        else:
                            if ( not inMacro and orgLine.startswith("#") and  line.endswith("\\") ):
                                inMacro = True
                            elif ( inMacro and not line.endswith("\\")):
                                inMacro = False

                            ''' Keeping track of preprocessor directives '''    
                            match = re.findall('^#\s*if.*', stripped(line))
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
                                        if ( found and fnMacro ):
                                            print orgLine,
                                            fDeclaration.append(orgLine)
                                            if ( not mcrCount ):
                                                break
                                            
                                        if ( len(preProcessorQ)  ):
                                            preProcessorQ.pop()
                                        
                                if ( "#else" in orgLine and found and not preProcessorQIgn and mcrCount):
                                    print orgLine,
                                    fDeclaration.append(orgLine)

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
        if ( ( funcNameCln != "if" ) and ( funcNameCln != "while" ) and ( funcNameCln != "for" ) and ( funcNameCln != "return" ) and ( funcNameCln != "switch" )  and len(funcNameCln) > 0 and not funcNameCln == funcName ):  
            if not ( ( funcNameCln in ntFoundFunc) or ( funcNameCln in funcMap ) ):
                print "Adding Function "+funcNameCln
                fListCln.append(funcNameCln)

    ''' Begins the recursive search for confirmed function calls '''
    for funcNameCln in fListCln:
        recFuncSearch(rootPath, funcNameCln, str(root)+"/"+filename)
            
    if ( len(fList) or done ):
        ''' Declaration is found and its either a macro or function pointer '''
        fDeclaration.append("\n")
        return
                        
    if (not found):
        ''' Function declaration is not found '''
        ntFoundFunc.add(funcName)
        rootPath = rootFile
        fHdrCln = funcName
        print funcName+" - definition is not found - "+rootPath
        return
    else:
        ''' Generic function header is found '''
        fHdrCln = fHdr.split('(',2)[0]
        print fHdrCln
        found = False
        fDeclaration.append("\n")

    ''' Search begins for function definitions '''
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
                fnMacro = False
                fList = []
                for line in inF:
                    orgLine = line
                    line = stripped(line)

                    cStart += line.count('/*');
                    cEnd += line.count('*/');

                    ''' Function definition match is easier coz lengthier header removed unwanted matches '''
                    if fHdrCln in line and ( cStart == cEnd ) and ( fHdrCln == line.split("(",2)[0] ) and ( not line.endswith(";") ):
                        ln = line
                        found = True

                        sCount = 0
                        eCount = 0                       

                        fDefinition.append("/* file: "+str(root) + "/" + str(filename)+" */\n")

                        ''' Flushing of preprocessor directives '''
                        for i in range( len(preProcessorQ) ):
                            fDefinition.append(preProcessorQ.popleft())

                        ''' Looking for possible function calls within the function body '''
                        while True:
                            orgLine = ln
                            i = 0
                            if ( ln.count('(') and sCount > 0 and ( cStart == cEnd ) and (not ln.startswith("//") ) and ( not ln.startswith("#") ) and not fHdrCln in ln ):
                                paraList = ln.split("(");
                                for slc in paraList:
                                    i += 1
                                    if ( slc != fHdrCln and i < len(paraList) ):
                                        if ( slc.count('\'') != 1 or slc.count('\"') != 1 or  slc.count('//') != 1 or slc.count('/*') != 1 ):
                                            if( not slc.strip().endswith(("=","'","+","-","/","*")) ):
                                                fList.append(slc)
                             
                            print orgLine,
                            fDefinition.append(orgLine)
                            
                            sCount += ln.count('{');
                            eCount += ln.count('}');
                            cStart += ln.count('/*');
                            cEnd += ln.count('*/');
                            line = stripped(ln)

                            ''' When the count of brackets equals, it signs the end of the function body '''
                            if ( ( sCount == eCount) and (eCount != 0)):
                                break

                            ln = inF.next()

                        if ( not mcrCount ):
                            break
                        
                    else:
                        if ( not inMacro and orgLine.startswith("#") and  line.endswith("\\") ):
                            inMacro = True
                        elif ( inMacro and not line.endswith("\\")):
                            inMacro = False

                        sCount += line.count('{');
                        eCount += line.count('}');

                        ''' Keeping track of preprocessor directives ''' 
                        if ( sCount == eCount ):
                            match = re.findall('^#\s*if.*', stripped(line))
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

                                        if ( found ):
                                            print orgLine,
                                            fDefinition.append(orgLine)
                                            if ( not mcrCount ):
                                                break
                                            
                                        if ( len(preProcessorQ)  ):
                                            preProcessorQ.pop()
                                        
                                if ( "#else" in orgLine and found and (not preProcessorQIgn) and mcrCount ):
                                    print orgLine,
                                    fDefinition.append(orgLine)

                                if ( "#elif" in orgLine ):
                                    preProcessorQ.append(orgLine)

                ''' Cleaning potential function calls '''
                fListCln = []                    
                for funcName in fList:   
                    funcNameCln = cleanFunctionName(funcName) 
                    if ( ( funcNameCln != "if" ) and ( funcNameCln != "while" ) and ( funcNameCln != "for" ) and ( funcNameCln != "return" ) and ( funcNameCln != "switch" ) and len(funcNameCln) > 0 ):                        
                        if not ( ( funcNameCln in ntFoundFunc) or ( funcNameCln in funcMap ) ):
                            print "Adding Function "+funcNameCln
                            fListCln.append(funcNameCln)

                ''' Begins the recursive search for confirmed function calls '''
                for funcNameCln in fListCln:
                    recFuncSearch(rootPath, funcNameCln, str(root)+"/"+filename)

                if ( found ):
                    return

    if ( not found ):
        print "Function Body is not found - "+funcName
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
    functionName = "OPENSSL_malloc"

    recFuncSearch(path, functionName,".")

    ''' Writing all the header declarations '''
    if ( len(fDeclaration) ):
        thefile = open(functionName+".h",'w')
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
