import { z } from 'zod'

export const urlSchema = z
  .string()
  .trim()
  .min(1, 'A URL is required.')
  .max(4096, 'The URL exceeds the 4096-character limit.')
  .superRefine((value, context) => {
    let parsed: URL
    try {
      parsed = new URL(value)
    } catch {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'Enter a valid absolute URL.' })
      return
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'Only HTTP and HTTPS URLs are supported.' })
    }
    if (parsed.username || parsed.password) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'Credentials in URLs are not accepted.' })
    }
  })
