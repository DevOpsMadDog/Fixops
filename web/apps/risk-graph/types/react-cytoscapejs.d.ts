declare module 'react-cytoscapejs' {
  import { Component } from 'react'
  import Cytoscape from 'cytoscape'

  interface CytoscapeComponentProps {
    elements: any[]
    style?: React.CSSProperties
    stylesheet?: any[]
    layout?: any
    cy?: (cy: Cytoscape.Core) => void
    [key: string]: any
  }

  export default class CytoscapeComponent extends Component<CytoscapeComponentProps> {}
}
