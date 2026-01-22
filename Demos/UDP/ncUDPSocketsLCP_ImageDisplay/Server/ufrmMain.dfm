object Form1: TForm1
  Left = 0
  Top = 0
  BorderIcons = [biSystemMenu, biMinimize]
  Caption = 'UDP Server - Image Display'
  ClientHeight = 231
  ClientWidth = 802
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  Position = poScreenCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  TextHeight = 13
  object Image1: TImage
    Left = 600
    Top = 72
    Width = 192
    Height = 145
  end
  object memLog: TMemo
    AlignWithMargins = True
    Left = 5
    Top = 69
    Width = 587
    Height = 157
    Margins.Left = 5
    Margins.Top = 0
    Margins.Right = 5
    Margins.Bottom = 5
    Align = alLeft
    ReadOnly = True
    ScrollBars = ssVertical
    TabOrder = 0
    OnKeyDown = memLogKeyDown
  end
  object pnlToolbar: TPanel
    Left = 0
    Top = 0
    Width = 802
    Height = 37
    Align = alTop
    BevelOuter = bvNone
    FullRepaint = False
    TabOrder = 1
    object btnActivate: TButton
      AlignWithMargins = True
      Left = 5
      Top = 5
      Width = 105
      Height = 27
      Margins.Left = 5
      Margins.Top = 5
      Margins.Right = 5
      Margins.Bottom = 5
      Align = alLeft
      Caption = 'Start UDP Server'
      TabOrder = 0
      OnClick = btnActivateClick
    end
    object pblPort: TPanel
      AlignWithMargins = True
      Left = 115
      Top = 3
      Width = 687
      Height = 31
      Margins.Left = 0
      Margins.Right = 0
      Align = alClient
      BevelOuter = bvNone
      FullRepaint = False
      TabOrder = 1
      object edtPort: TSpinEdit
        AlignWithMargins = True
        Left = 0
        Top = 5
        Width = 121
        Height = 22
        Margins.Left = 0
        Margins.Top = 5
        Margins.Right = 5
        Margins.Bottom = 5
        Align = alLeft
        MaxValue = 0
        MinValue = 0
        TabOrder = 0
        Value = 16233
        OnChange = edtPortChange
      end
    end
  end
  object Panel1: TPanel
    Left = 0
    Top = 37
    Width = 802
    Height = 32
    Margins.Left = 5
    Margins.Top = 0
    Margins.Right = 5
    Margins.Bottom = 5
    Align = alTop
    BevelOuter = bvNone
    FullRepaint = False
    TabOrder = 2
    object btnSendCommand: TButton
      AlignWithMargins = True
      Left = 5
      Top = 0
      Width = 105
      Height = 27
      Margins.Left = 5
      Margins.Top = 0
      Margins.Right = 0
      Margins.Bottom = 5
      Align = alLeft
      Caption = 'Send Command'
      TabOrder = 0
      OnClick = btnSendCommandClick
    end
    object Panel2: TPanel
      AlignWithMargins = True
      Left = 110
      Top = 3
      Width = 692
      Height = 26
      Margins.Left = 0
      Margins.Right = 0
      Align = alClient
      BevelOuter = bvNone
      FullRepaint = False
      TabOrder = 1
      object Label1: TLabel
        AlignWithMargins = True
        Left = 3
        Top = 6
        Width = 51
        Height = 17
        Margins.Top = 6
        Align = alLeft
        Caption = 'Command:'
        ExplicitHeight = 13
      end
      object edtCommandData: TEdit
        AlignWithMargins = True
        Left = 57
        Top = 0
        Width = 630
        Height = 21
        Margins.Left = 0
        Margins.Top = 0
        Margins.Right = 5
        Margins.Bottom = 5
        Align = alClient
        TabOrder = 0
        Text = 'TITLE|New Window Title'
        TextHint = 'Enter command to send to last client'
      end
    end
  end
  object UDPServer: TncUDPServerLCP
    Broadcast = True
    OnCommand = UDPServerCommand
    Left = 224
    Top = 120
  end
end
