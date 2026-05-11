# Current Investigation Status Review

Please generate the next investigation plan based on the following information.

### "Hunting Objective" for this round

<hunting_objective>{hunting_objective}</hunting_objective>

### Current Iteration

<iteration_count>{iteration_count}</iteration_count>

### "Investigation Findings"

The following are all the investigation findings, questions, and conclusions collected so far:

<findings>{findings}</findings>

---

**Core Task**:

Synthesizing all the information above ("Hunting Objective", "Current Iteration", and **especially** "Investigation Findings"), please determine:

1.  Is further investigation needed to complete the "Hunting Objective"?
2.  If so, what are the most reasonable, effective, and parallelizable investigation questions for the next step?

If the "Hunting Objective" has been achieved, or if no further investigation is possible, please return an empty plan (`current_plan` is an empty list).

**Please strictly follow the JSON format defined in the system prompt for your output.**
