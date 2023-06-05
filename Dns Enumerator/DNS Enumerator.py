
from reportlab.pdfgen import canvas
import dns.resolver

pdf = canvas.Canvas(filename="out1.pdf")

def mxResolver(domain,y): 
    answers = dns.resolver.resolve(domain, 'MX')
    for rdata in answers:
        mxLookup = 'Host', rdata.exchange, 'has preference', rdata.preference
        #print(str(temp))
        if "eo.outlook.com" in str(mxLookup):
            pdf.drawString(30,y,"Old Microsoft Forefront Mx Record Detected ")
            y = y - 25
            pdf.drawString(30,y,str(mxLookup))
            y = y - 25
            return y
        elif "mail.protection.outlook.com" in str(mxLookup):
            pdf.drawString(30,y,"New EOP MX Record Detected ")
            y = y - 25
            pdf.drawString(30,y,str(mxLookup))
            y = y - 25
            return y
        elif "barracudanetworks.com" in str(mxLookup):
           pdf.drawString(30,y,"Barracuda Spam Filter Detected " + str(mxLookup))
           y = y - 25
           return y
        elif "ASPMX.L.GOOGLE.COM" in str(mxLookup):
           pdf.drawString(30,y,"Gmail Detected " + str(mxLookup))
           y = y - 25
           return y
        elif "mimecast.com" in str(mxLookup):
           pdf.drawString(30,y,"Mimecast Detected " + str(mxLookup))
           y = y - 25
           return y
        else:
           pdf.drawString(30,y,"Other Mail Provider Detected " + str(mxLookup))
           y = y - 25
           return y
               
          
def spfLookup(domain,y):
     hardfail = "-all"
     softfail = "~all"
     status = "null"
     redirect = "redirect"

     answers = dns.resolver.resolve(domain, 'TXT')
     #print(answers)
     spfRecordCount = 1

     for rdata in answers:
          try:
               if ( hardfail in str(rdata) ):
                    status = "Hard Spf Fail Found"
                    #print("Hard fail found")
                    pdf.drawString(30,y,status)
                    y = y - 25
                    #return y
               elif (softfail in str(rdata)):
                    #print("Soft fail found")
                    status = "Soft Spf Fail Found"
                    pdf.drawString(30,y,status)
                    y = y - 25
                    #return y
               elif (redirect in str(rdata)):
                    status = dns.resolver.resolve(domain, 'TXT')
                    print(status)
                    pdf.drawString(30,y,status)
                    y = y - 25
                   # return y
          except:
               status = "Invalid SPF Record"
               pdf.drawString(30,y,status)
               y = y - 25
               #return y
     for ipval in answers:
          #print(ipval)
          #print(spfRecordCount)
          #ipval.to_text())
          pdf.drawString(30,y,f"SPF Record Count {spfRecordCount}: ")
          y = y - 25
          pdf.drawString(30,y,ipval.to_text())
          y = y - 25
          spfRecordCount = spfRecordCount + 1
          
     return y
def dkimLookup(domain,y):
     #Set them to None's for checks later
     checkGoogleSelector = None
     selector1 = None
     
     #Check if Google DKIM Exists 
     try:
          checkGoogleSelector = dns.resolver.resolve('google._domainkey.' + domain, 'txt')
     except:
          pass
     
     #Check if O365 DKIM Exists
     try:
          selector1 = dns.resolver.resolve('selector1._domainkey.' + domain, 'CNAME')
          selector2 = dns.resolver.resolve('selector2._domainkey.' + domain, 'CNAME')
     except:
          pass
     
     #If Google DKIM exists Write to PDF
     if(checkGoogleSelector is not None):
          pdf.drawString(30,y,"Google DKIM Detected")
          y = y - 25
          for rdata in checkGoogleSelector:
               print(rdata)
               if(checkGoogleSelector ):
                         print(rdata)
                         pdf.drawString(30,y,"Google DKIM Selector Found " +str(rdata))
                         y = y - 25
     #If O365 DKIM exists Write to PDF
     if(selector1 is not None):
          pdf.drawString(30,y,"O365 DKIM Detected ")
          y = y - 25
          #Pull Selector 1 for O365
          try:
               for rdata in selector1:
                    pdf.drawString(30,y,"First O365 DKIM Selector Found " +str(rdata))
               y = y - 25
          except:
               status = "No DKIM Selector 1 Found"
               pdf.drawString(30,y, status)
               y = y - 25
          #Pull Selector 2 for O365
          try:
               for rdata in selector2:
                    pdf.drawString(30,y,"Second O365 DKIM Selector Found " + str(rdata))
               y = y - 25
          except: 
               status = "No DKIM Selector 2 Found"
               pdf.drawString(30,y,status)
               y = y - 25

     #If we cant find either DKIM setup for Google or O365 Assume Nothing Set
     #In the future add Support for other mail providers
     # If we return None for dkim catch exception return nothing found. 
     print(checkGoogleSelector, selector1)
     try:
          if None in (checkGoogleSelector or selector1) :
               pdf.drawString(30,y,"No DKIM Detected ")
               y = y - 25
               return(y)
     except:
          pdf.drawString(30,y,"No DKIM Detected ")
          y = y - 25
          return(y)
          #Return Y Axis     
     return y
        

def dmarcLookup(domain,y):
     reject = "reject"
     quarantine = "quarantine"
     none = "none"
     try:
          answers = dns.resolver.resolve('_dmarc.' + domain, 'TXT')
          for rdata in answers:
               #pdf.drawString(30,y,str(rdata))
               if ( reject in str(rdata) ):
                    status = "Dmarc In Reject Mode"
                    pdf.drawString(30,y,status)
                    y = y - 25
                    pdf.drawString(30,y,str(rdata))
               elif(quarantine in str(rdata)):
                    status = "Dmarc in Quarantine Mode"
                    pdf.drawString(30,y,status)
                    y = y - 25
                    pdf.drawString(30,y,str(rdata))
               elif(none in str(rdata)):
                    status = "Dmarc in None Mode"
                    pdf.drawString(30,y,status)
                    y = y - 25
                    pdf.drawString(30,y,str(rdata))
     except:
          status = "No Dmarc Record Found"
          pdf.drawString(30,y,status)
          y = y - 25


def main():
    #cps.k12.ny.us
    domain = "wiggin.com"
    y = 770
    pdf.drawString(250,y, "Domain " + domain)
    y = y - 25
    y = mxResolver(domain, y)
    y = spfLookup(domain, y)
    y = dkimLookup(domain,y)
    dmarcLookup(domain,y)
 
    pdf.save()

if __name__ == "__main__":
    main()