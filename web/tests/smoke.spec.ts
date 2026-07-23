import { expect, test } from '@playwright/test'

test('renders no-fetch analysis form', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('heading', { name: /malicious url triage/i })).toBeVisible()
  await expect(page.getByText('NO-FETCH MODE')).toBeVisible()
  await expect(page.getByLabel('URL to analyze')).toBeVisible()
})
