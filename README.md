# Invoke-BloodHound
Simulate sharphound but coding in powershell...

## Specially Thanks to:
- #### [ConvertTo-Json Powershell 2](https://github.com/EliteLoser/ConvertTo-Json)
  Mark: I merged his repository into my scripts XD (with author permission: [portal](https://github.com/EliteLoser/ConvertTo-Json/issues/5))
- #### [@EliteLoser](https://github.com/EliteLoser)

## Work in progress now
- Ugly code. ¯\\_(ツ)_/¯

## Todo
- Convert SID when information collecting. -Done
- Resolve ACEs (I just reolve IdentityReference to SecurityIdentifier). -Done
- Make a converter to process hole the data.
- Some parts of code didn't make sense now.

## Output data screenshots
- Main attributes  
![AllUsers.json](https://user-images.githubusercontent.com/30458572/158513355-c6777ac9-23c4-4f0b-a627-a870cc978819.png)

- ACEs  
![ACEs](https://user-images.githubusercontent.com/30458572/158513590-5b8a96d2-fc22-424a-8b88-ff5e6e6d9cf4.png)


## Script running screenshots
- Server 2019 (Env: DotNet 4.x)  
![2019-image](https://user-images.githubusercontent.com/30458572/158213041-0c42489c-3821-4ad2-82e7-3e10048c72ea.png)
 
- Server 2008/ windows 7 (Env: DotNet 3.0, powershell 2.0)  
![2008-image](https://user-images.githubusercontent.com/30458572/158213221-41554c2e-327a-4049-8754-e57d2f96254f.png)
