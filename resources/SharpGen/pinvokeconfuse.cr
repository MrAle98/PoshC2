<project baseDir="{0}" outputDir="{1}" xmlns="http://confuser.codeplex.com">
    <module path="{2}">
      <rule pattern="true" inherit="false">
         <protection id="rename" />
         <protection id="anti dump" />      
         <protection id="anti ildasm" />     
         <protection id="anti tamper" />    
          <protection id="ctrl flow" />        
         <protection id="invalid metadata" /> 
      </rule>
    </module>
</project>
