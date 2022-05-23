<project outputDir="{1}" baseDir="{0}" xmlns="http://confuser.codeplex.com">
  <module path="{2}">
    <rule pattern="true" inherit="false">
     <protection id="rename" />      
     <protection id="anti ildasm" />
     <protection id="ctrl flow" />        
     <protection id="invalid metadata" /> 
    </rule>
  </module>
</project>
