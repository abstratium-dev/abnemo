---
trigger: model_decision
description: when working on styles
globs: src/main/webui/**/*.scss
---

CSS styles should normally be added to the global file `web_static/styles.css` rather than in individual files, as they can be reused by other components. It is important not to duplicate styles that already exist in the global styles file.

Dark mode must be supported, meaning that all colours must be taken from that main styles.css file.