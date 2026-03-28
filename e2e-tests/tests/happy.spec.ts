import { test, expect } from '@playwright/test';
import { AuthPage } from '../pages/auth.page';
import { TrafficPage } from '../pages/traffic.page';

test.describe('Abnemo E2E Tests', () => {
  const TEST_EMAIL = 'test@abstratium.dev';
  const TEST_PASSWORD = 'secretLong';
  const TEST_BEGIN_TIME = '2025-12-31T23:00';
  const TEST_END_TIME = '2025-12-31T23:30';
  
  test('should sign in, view traffic, and manage accept-list filters', async ({ page }) => {
    console.log('=== Starting E2E Test ===');
    
    const authPage = new AuthPage(page);
    const trafficPage = new TrafficPage(page);
    
    // Step 1: Navigate to the application
    console.log('\n--- Step 1: Navigate to application ---');
    await trafficPage.goto();
    
    // Step 2: Sign in
    console.log('\n--- Step 2: Sign in ---');
    await trafficPage.clickSignIn();
    await authPage.authenticate(TEST_EMAIL, TEST_PASSWORD);
    
    // Step 3: Wait for authentication to complete
    console.log('\n--- Step 3: Verify authentication ---');
    await trafficPage.waitForAuthenticated();
    
    // Step 4: Load test traffic data
    console.log('\n--- Step 4: Load traffic data ---');
    await trafficPage.loadTrafficData(TEST_BEGIN_TIME, TEST_END_TIME);
    
    // Disable accept-list to ensure all traffic is visible initially
    await trafficPage.disableAcceptList();
    
    // Reload data to ensure all rows are shown
    await trafficPage.loadTrafficData(TEST_BEGIN_TIME, TEST_END_TIME);
    await page.waitForTimeout(1000);
    
    // Step 5: Verify initial traffic data (should show 5 total IPs)
    console.log('\n--- Step 5: Verify initial traffic data ---');
    const totalIps = await trafficPage.getTotalIpCount();
    expect(totalIps).toBe(5);
    console.log(`✓ Total IPs: ${totalIps}`);
    
    const initialVisibleIps = await trafficPage.getVisibleIpAddresses();
    const initialVisibleCount = initialVisibleIps.length;
    console.log(`✓ Initially ${initialVisibleCount} IPs are visible (some may be filtered by existing filters)`);
    
    // Verify at least the public IPs are visible
    expect(initialVisibleIps).toContain('8.8.8.8');
    expect(initialVisibleIps).toContain('93.184.216.34');
    expect(initialVisibleIps).toContain('1.1.1.1');
    console.log('✓ Public IPs are visible');
    
    // Step 6: Add an accept-list filter to hide private IPs
    console.log('\n--- Step 6: Add accept-list filter ---');
    const filterPattern = '^(192\\.168\\.|10\\.)';
    const filterDescription = 'Hide private network traffic';
    await trafficPage.addAcceptListFilter(filterPattern, filterDescription);
    
    // Step 7: Verify filter was created successfully
    console.log('\n--- Step 7: Verify filter was created ---');
    
    // Verify the filter exists
    await trafficPage.verifyFilterExists(filterPattern, filterDescription);
    console.log('✓ Filter exists in the list');
    
    // Reload the data to ensure filter is applied
    await trafficPage.loadTrafficData(TEST_BEGIN_TIME, TEST_END_TIME);
    await page.waitForTimeout(1000);
    
    const visibleIpsAfterFilter = await trafficPage.getVisibleIpAddresses();
    console.log(`✓ After adding filter: ${visibleIpsAfterFilter.length} IPs visible`);
    
    // Verify private IPs are not visible (they should be filtered)
    expect(visibleIpsAfterFilter).not.toContain('192.168.1.100');
    expect(visibleIpsAfterFilter).not.toContain('10.0.0.50');
    console.log('✓ Private IPs are filtered out');
    
    // Verify public IPs are still visible
    expect(visibleIpsAfterFilter).toContain('8.8.8.8');
    expect(visibleIpsAfterFilter).toContain('93.184.216.34');
    expect(visibleIpsAfterFilter).toContain('1.1.1.1');
    console.log('✓ Public IPs are still visible');
    
    // Step 8: Edit the filter
    console.log('\n--- Step 8: Edit filter ---');
    const updatedDescription = 'Hide private network traffic (edited)';
    await trafficPage.editFilter(filterPattern, filterDescription, updatedDescription);
    
    // Verify the edit was successful
    await trafficPage.verifyFilterExists(filterPattern, updatedDescription);
    console.log('✓ Filter edited successfully');
    
    // Step 9: Delete the filter
    console.log('\n--- Step 9: Delete filter ---');
    await trafficPage.deleteFilter(filterPattern, updatedDescription);
    
    // Verify filter is deleted
    await trafficPage.verifyFilterNotExists(filterPattern, updatedDescription);
    console.log('✓ Filter deleted successfully');
    
    console.log('\n=== E2E Test Completed Successfully ===');
  });
});
