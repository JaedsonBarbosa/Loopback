using System;
using System.Collections.ObjectModel;
using System.Windows;

namespace Loopback
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        LoopUtil _loop;
        ObservableCollection<LoopUtil.AppContainer> appFiltered;

        public MainWindow()
        {
            InitializeComponent();
            _loop = new LoopUtil();
            appFiltered = new ObservableCollection<LoopUtil.AppContainer>(_loop.Apps);
            dgLoopback.ItemsSource = appFiltered;
        }

        private void Salvar(object sender, RoutedEventArgs e)
        {
            if (_loop.SaveLoopbackState())
            {
                Log("Modificações salvas sem nenhum problema.");
            }
            else
            {
                Log("Erro desconhecido ao salvar");
            }
        }

        private void Atualizar(object sender, RoutedEventArgs e)
        {
            _loop.LoadApps();
            appFiltered.Clear();
            _loop.Apps.ForEach(appFiltered.Add);
            dgLoopback.Items.Refresh();
            Log("Lista atualizada com sucesso");
        }

        private void Log(String logtxt)
        {
            txtStatus.Text = DateTime.Now.ToString("hh:mm:ss ") + logtxt;
        }
    }
}
