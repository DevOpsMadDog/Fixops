# fixops-blended-enterprise/

**Purpose:** Comprehensive enterprise reference implementation (backend, frontend, infra) used for
competitive benchmarking and storytelling. Not actively wired into the lightweight demo service.

**Gotchas**
- Contains large dependency trees (Node, Terraform). Avoid editing unless you intend to maintain the
  full stack.
- Use this directory as inspiration when mapping features but prioritise the smaller `backend/`
  service for runnable demos.
