/**
 * Main JavaScript file for the IBC Ticketing System
 */

document.addEventListener('DOMContentLoaded', function() {
  // Handle mobile menu toggle
  const menuToggle = document.querySelector('.menu-toggle');
  const sidebar = document.querySelector('.sidebar');
  
  if (menuToggle) {
      menuToggle.addEventListener('click', function() {
          sidebar.classList.toggle('show');
      });
  }
  
  // Handle alert dismissal
  const alerts = document.querySelectorAll('.alert');
  
  alerts.forEach(alert => {
      setTimeout(() => {
          alert.style.opacity = '0';
          setTimeout(() => {
              alert.style.display = 'none';
          }, 500);
      }, 5000);
  });
  
  // QR Code Scanner Integration (placeholder for future implementation)
  // This will be replaced with actual QR scanner code
  class QRScanner {
      constructor(containerId, callback) {
          this.container = document.querySelector(containerId);
          this.callback = callback;
          
          // Mock scanner for now
          this.initMockScanner();
      }
      
      initMockScanner() {
          if (!this.container) return;
          
          // Show the scanner container
          this.container.style.display = 'block';
          
          // Add mock scanner UI
          this.container.innerHTML = `
              <div class="mock-scanner">
                  <div class="scanner-header">
                      <h3>QR Scanner</h3>
                      <p>Point your camera at a QR code</p>
                  </div>
                  <div class="scanner-viewport">
                      <div class="scanner-lines"></div>
                  </div>
                  <div class="scanner-footer">
                      <button id="mock-scan-btn" class="btn btn-primary">Simulate Scan</button>
                  </div>
              </div>
          `;
          
          // Add event listener to mock scan button
          const mockScanBtn = document.getElementById('mock-scan-btn');
          if (mockScanBtn) {
              mockScanBtn.addEventListener('click', () => {
                  // Generate a random UUID to simulate a ticket scan
                  const uuid = this.generateMockUUID();
                  this.callback(uuid);
              });
          }
      }
      
      generateMockUUID() {
          // This generates a mock UUID for testing
          return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
              const r = Math.random() * 16 | 0;
              const v = c === 'x' ? r : (r & 0x3 | 0x8);
              return v.toString(16);
          });
      }
  }
  
  // Make QRScanner available globally
  window.QRScanner = QRScanner;
  
  // Initialize date range pickers if they exist
  const dateFrom = document.getElementById('date_from');
  const dateTo = document.getElementById('date_to');
  
  if (dateFrom && dateTo) {
      // Set default date values (last 7 days)
      const today = new Date();
      const weekAgo = new Date();
      weekAgo.setDate(today.getDate() - 7);
      
      // Format dates to YYYY-MM-DD
      dateTo.value = today.toISOString().split('T')[0];
      dateFrom.value = weekAgo.toISOString().split('T')[0];
      
      // Ensure dateTo is always >= dateFrom
      dateFrom.addEventListener('change', function() {
          if (new Date(dateFrom.value) > new Date(dateTo.value)) {
              dateTo.value = dateFrom.value;
          }
      });
      
      dateTo.addEventListener('change', function() {
          if (new Date(dateTo.value) < new Date(dateFrom.value)) {
              dateFrom.value = dateTo.value;
          }
      });
  }
  
  // Dynamic ticket price display based on selected ticket type
  const ticketTypeSelect = document.getElementById('id_ticket_type');
  const ticketPriceInfo = document.querySelector('.ticket-price-info');
  
  if (ticketTypeSelect && ticketPriceInfo) {
      ticketTypeSelect.addEventListener('change', function() {
          const selectedOption = ticketTypeSelect.options[ticketTypeSelect.selectedIndex].text;
          
          // Highlight the selected ticket type in the price info
          const priceItems = ticketPriceInfo.querySelectorAll('li');
          priceItems.forEach(item => {
              if (item.textContent.includes(selectedOption)) {
                  item.style.fontWeight = 'bold';
                  item.style.color = 'var(--primary)';
              } else {
                  item.style.fontWeight = 'normal';
                  item.style.color = 'inherit';
              }
          });
      });
  }
});