<project outputDir="{1}" baseDir="{0}" xmlns="http://confuser.codeplex.com">
  <module path="{2}">
    <rule pattern="true" inherit="false">
          <protection id="rename" />
         <protection id="anti debug" />      
         <protection id="anti dump" />      
         <protection id="anti ildasm" />     
         <protection id="anti tamper" />    
         <protection id="constants" />      
          <protection id="ctrl flow" />        
    </rule>
  </module>
</project>
