# Page snapshot

```yaml
- generic [ref=e1]:
  - alert [ref=e2]
  - main [ref=e3]:
    - generic [ref=e6]:
      - generic [ref=e7]:
        - generic [ref=e8]: S
        - heading "Sign in to Sigil" [level=1] [ref=e9]
        - paragraph [ref=e10]: Automated security auditing for AI agent code.
      - generic [ref=e11]:
        - button "Sign In" [ref=e12] [cursor=pointer]
        - button "Register" [ref=e13] [cursor=pointer]
      - generic [ref=e15]:
        - generic [ref=e16]:
          - generic [ref=e17]:
            - generic [ref=e18]: Email address
            - textbox "Email address" [active] [ref=e19]:
              - /placeholder: you@company.com
          - generic [ref=e20]:
            - generic [ref=e21]:
              - generic [ref=e22]: Password
              - button "Forgot password?" [ref=e23] [cursor=pointer]
            - textbox "Password" [ref=e24]:
              - /placeholder: Enter your password
          - button "Sign in" [ref=e25] [cursor=pointer]
        - generic [ref=e30]: Or sign in with
        - generic [ref=e31]:
          - button "Continue with GitHub" [ref=e32] [cursor=pointer]:
            - img [ref=e33]
            - text: Continue with GitHub
          - button "Continue with Google" [ref=e35] [cursor=pointer]:
            - img [ref=e36]
            - text: Continue with Google
      - paragraph [ref=e41]:
        - text: Don't have an account?
        - button "Create one" [ref=e42] [cursor=pointer]
```